//! RF05a — the execution view of a finalized `Policy`.
//!
//! `Policy` stays the document: KDL emission, the effective hash,
//! provenance, and validation all read it in the same order and
//! meaning as before. The per-request path instead consults a
//! [`PreparedPolicy`], built once where the tool set becomes final
//! (`Auditor::new`, a session's policy swap) and shared across both
//! relay directions behind an `Arc`.
//!
//! The view carries only what is derivable from the policy itself —
//! the tool-name index and each tool's [`PreparedTool`]. No OS state,
//! no request state, no session state: nothing in here can go stale
//! while the document it wraps is unchanged, and a policy update path
//! replaces the whole view rather than re-preparing in place, so a
//! stale index can never be consulted against a newer document.

use std::collections::HashMap;

use super::opaque::OpaqueMatcher;
use super::{Policy, ResolvedInputResponses, SideEffect, ToolPolicy};

/// What a tool-name lookup returns: the matched `ToolPolicy` plus the
/// prepared rules built for that exact `tools` entry.
#[derive(Clone, Copy)]
pub struct ToolHit<'p> {
    /// The entry the lookup picked — the same `ToolPolicy` the linear
    /// `iter().find` scans returned (first match, or first *allowed*
    /// match, depending on the lookup).
    pub(crate) tool: &'p ToolPolicy,
    /// The entry's prepared rules — built once by
    /// [`PreparedPolicy::new`]. `None` when the lookup ran on a bare
    /// `Policy` (the standalone `check_request` path), where callers
    /// derive each per call exactly as they always did.
    pub(crate) prepared: Option<&'p PreparedTool>,
}

impl<'p> ToolHit<'p> {
    /// `tool.side_effect` parsed — the prepared value when the index
    /// built one, the same `parse(...).ok()` the request path ran
    /// otherwise.
    pub(crate) fn side_effect(&self) -> Option<SideEffect> {
        match self.prepared {
            Some(p) => p.side_effect,
            None => self
                .tool
                .side_effect
                .as_deref()
                .and_then(|raw| SideEffect::parse(raw).ok()),
        }
    }

    /// `tool.input_responses.resolve(tool.has_security_contract())` —
    /// prepared when the index built it.
    pub(crate) fn resolved_input_responses(&self) -> ResolvedInputResponses {
        match self.prepared {
            Some(p) => p.resolved_input_responses,
            None => self
                .tool
                .input_responses
                .resolve(self.tool.has_security_contract()),
        }
    }

    /// The prepared `args_schema` plan for this tool — `None` when the
    /// tool carries no schema or the lookup ran on a bare `Policy`
    /// (the standalone path prepares per call, exactly as before).
    pub(crate) fn schema_plan(&self) -> Option<&'p ToolSchema> {
        self.prepared.and_then(|p| p.args_schema.as_ref())
    }
}

/// Per-tool execution rules derivable from `ToolPolicy` alone — built
/// once by [`PreparedPolicy::new`] so no request pays for them again.
#[derive(Debug)]
pub struct PreparedTool {
    /// `OpaqueMatcher::build(&tool.opaque_fields)` — the trie the
    /// classified walk descends per request; `None` for tools without
    /// opaque declarations, exactly as `build` reports.
    pub(crate) opaque: Option<OpaqueMatcher>,
    /// `tool.side_effect` parsed once (`None` when absent or
    /// unparsable — the `parse(...).ok()` the request path ran).
    pub(crate) side_effect: Option<SideEffect>,
    /// `tool.input_responses.resolve(tool.has_security_contract())`.
    pub(crate) resolved_input_responses: ResolvedInputResponses,
    /// The `args_schema` execution plan — `None` when the tool carries
    /// no schema. See [`ToolSchema`].
    pub(crate) args_schema: Option<ToolSchema>,
}

/// The `args_schema` execution plan for one prepared tool — RF05b.
///
/// `Inline` is the shape KDL-loaded policies produce: the loader
/// resolves `@file` spellings to inline JSON at parse time
/// (`Policy::inlined_schemas`), so a prepared view only ever sees a
/// `@`-spelling on programmatically built documents that skipped that
/// step. `File` covers that case without changing what a request does:
/// the checker still calls `schema_validator::resolve_schema` per
/// call (the cwd-scoped, no-follow read is the contract), and this
/// single-entry memo keys on the *resolved bytes* — identical bytes
/// reuse one parse, a rewrite yields a fresh plan. Never keyed on the
/// path itself.
#[derive(Debug)]
pub enum ToolSchema {
    /// Parsed once at `PreparedPolicy::new`; every request in the
    /// session shares the document and its `$ref`/`pattern` memos.
    Inline(crate::schema_spec::prepared::PreparedSchema),
    /// Prepared lazily on the resolved bytes — see the enum docs.
    File(std::sync::Mutex<Option<FileSchemaEntry>>),
}

/// The `File` memo slot: which bytes the cached plan was built from,
/// plus the plan — `Arc` so a request evaluating a stale-now entry
/// finishes on the document it started with while a rewrite swaps in
/// the fresh one. A rewrite *replaces* the slot's entry: the
/// displaced plan drops once its last in-flight `Arc` drains, so a
/// long-lived `PreparedPolicy` never accumulates versions of the same
/// `@file` schema.
#[derive(Debug)]
pub struct FileSchemaEntry {
    content: Box<str>,
    prepared: std::sync::Arc<crate::schema_spec::prepared::PreparedSchema>,
}

impl ToolSchema {
    /// The prepared schema for `content` — the cache when the bytes
    /// match the last resolution, a fresh build when they do not.
    /// Only valid on `ToolSchema::File`; the checker guarantees it.
    pub(crate) fn file_plan(
        &self,
        content: &str,
    ) -> std::sync::Arc<crate::schema_spec::prepared::PreparedSchema> {
        let Self::File(slot) = self else {
            unreachable!("file_plan on a non-File ToolSchema")
        };
        let mut guard = slot.lock().unwrap();
        if let Some(entry) = guard.as_ref()
            && &*entry.content == content
        {
            return entry.prepared.clone();
        }
        let prepared = std::sync::Arc::new(crate::schema_spec::prepared::PreparedSchema::new(
            content.to_string(),
        ));
        *guard = Some(FileSchemaEntry {
            content: content.into(),
            prepared: prepared.clone(),
        });
        prepared
    }
}

/// Where a tool name sits in `policy.tools` — `first` reproduces
/// `iter().find(|t| t.name == name)`, `first_allowed` the
/// `find(.. && t.allowed)` / `any(.. && t.allowed)` lookups, exactly —
/// including duplicate names (policy load rejects them, but a
/// programmatically built `Policy` can still carry them and the
/// first-match asymmetry is observable: the denied entry answers
/// `find` while the allowed one answers admission).
#[derive(Debug, Clone, Copy)]
struct ToolSlot {
    first: usize,
    first_allowed: Option<usize>,
}

/// A finalized [`Policy`] plus the session-invariant execution rules
/// derived from it once — the tool-name index and each tool's
/// [`PreparedTool`].
///
/// Owns the document so the index's lifetime is the document's: the
/// view is never re-prepared in place. `Deref` exposes the wrapped
/// `Policy` unchanged — KDL emission, the effective hash, provenance,
/// `decide_mcp`, and every flag/vector reader see exactly the document
/// they saw before.
#[derive(Debug)]
pub struct PreparedPolicy {
    policy: Policy,
    /// `name → slots` — lookups only. The map is never enumerated, so
    /// its iteration order reaches no external array, document, or
    /// digest.
    index: HashMap<Box<str>, ToolSlot>,
    /// Parallel to `policy.tools` — same length, same order.
    tools: Vec<PreparedTool>,
}

impl PreparedPolicy {
    /// Build the execution view once, where the tool set is final —
    /// `Auditor::new` for the product session, `set_policy` wherever a
    /// policy is swapped. The `entry` API takes an owned key per
    /// `tools` entry (never per request); a duplicate name's transient
    /// `Box<str>` is dropped by `and_modify`, so the map keeps one copy
    /// per distinct name — the one bounded duplication a `HashMap`
    /// index needs since it cannot borrow `ToolPolicy::name`.
    /// No `tools` entry is cloned or rewritten; `tools[i]` describes
    /// `policy.tools[i]`.
    pub fn new(policy: Policy) -> Self {
        #[cfg(feature = "measure")]
        let _timer = crate::measure::Timer::new(&crate::measure::POLICY_PREPARE_NS);
        #[cfg(feature = "measure")]
        crate::measure::incr(&crate::measure::POLICY_PREPARE_CALLS, 1);
        let mut index: HashMap<Box<str>, ToolSlot> = HashMap::with_capacity(policy.tools.len());
        let mut tools = Vec::with_capacity(policy.tools.len());
        for (i, tool) in policy.tools.iter().enumerate() {
            index
                .entry(Box::<str>::from(tool.name.as_str()))
                .and_modify(|slot| {
                    if tool.allowed && slot.first_allowed.is_none() {
                        slot.first_allowed = Some(i);
                    }
                })
                .or_insert(ToolSlot {
                    first: i,
                    first_allowed: tool.allowed.then_some(i),
                });
            tools.push(PreparedTool {
                opaque: OpaqueMatcher::build(&tool.opaque_fields),
                side_effect: tool
                    .side_effect
                    .as_deref()
                    .and_then(|raw| SideEffect::parse(raw).ok()),
                resolved_input_responses: tool
                    .input_responses
                    .resolve(tool.has_security_contract()),
                args_schema: tool.args_schema.as_ref().map(|schema_ref| {
                    if schema_ref.starts_with('@') {
                        ToolSchema::File(std::sync::Mutex::new(None))
                    } else {
                        ToolSchema::Inline(crate::schema_spec::prepared::PreparedSchema::new(
                            schema_ref.clone(),
                        ))
                    }
                }),
            });
        }
        Self {
            policy,
            index,
            tools,
        }
    }

    /// The document this view was built over.
    pub fn document(&self) -> &Policy {
        &self.policy
    }

    /// Capacity-based estimate of the bytes the view owns beyond the
    /// wrapped document — the resident cost a session pays for O(1)
    /// lookups. Deterministic structural accounting, not an allocator
    /// reading: `HashMap::capacity()` counts elements the map can hold,
    /// a lower bound on its bucket array, so the total is an estimate
    /// rather than an exact allocation. `Vec` capacities and string
    /// buffers are exact; an A/B run compares the same formula on both
    /// sides either way.
    #[cfg(feature = "measure")]
    #[doc(hidden)]
    pub fn estimated_resident_bytes(&self) -> u64 {
        // Swiss-table maps carry one control byte per bucket.
        let mut n = std::mem::size_of::<Self>() - std::mem::size_of::<Policy>();
        n += self.index.capacity() * (std::mem::size_of::<(Box<str>, ToolSlot)>() + 1);
        for key in self.index.keys() {
            n += key.len();
        }
        n += self.tools.capacity() * std::mem::size_of::<PreparedTool>();
        for tool in &self.tools {
            if let Some(matcher) = &tool.opaque {
                n += matcher.heap_bytes();
            }
            match &tool.args_schema {
                Some(ToolSchema::Inline(schema)) => {
                    // The `PreparedSchema` object itself sits inside
                    // this `PreparedTool` (already in the
                    // `tools.capacity()` count) — add only what it
                    // owns on the heap.
                    n += schema.estimated_resident_bytes() as usize
                        - std::mem::size_of::<crate::schema_spec::prepared::PreparedSchema>();
                }
                Some(ToolSchema::File(slot)) => {
                    if let Some(entry) = slot.lock().unwrap().as_ref() {
                        n += entry.content.len()
                            + entry.prepared.estimated_resident_bytes() as usize;
                    }
                }
                None => {}
            }
        }
        n as u64
    }

    fn slot(&self, name: &str) -> Option<ToolSlot> {
        self.index.get(name).copied()
    }

    fn hit(&self, index: usize) -> ToolHit<'_> {
        ToolHit {
            tool: &self.policy.tools[index],
            prepared: Some(&self.tools[index]),
        }
    }
}

/// `&PreparedPolicy` dereferences to the wrapped document — read-only
/// `Policy` consumers keep working through the wrapper unchanged.
impl std::ops::Deref for PreparedPolicy {
    type Target = Policy;

    fn deref(&self) -> &Policy {
        &self.policy
    }
}

/// The tool-name index a policy gets checked against.
///
/// `Policy` answers with the linear `iter()` scans the checkers always
/// ran — the standalone `check_request` path, where building an index
/// would cost more than the one lookup it serves. `PreparedPolicy`
/// answers from the map built once per session. Both reproduce the
/// `find`/`any` semantics over `tools` bit for bit, including
/// duplicate-name ordering.
pub trait ToolIndex {
    /// The viewed policy document — the global rules and flags the
    /// checkers also read.
    fn document(&self) -> &Policy;
    /// `tools.iter().find(|t| t.name == name)` — the first entry
    /// regardless of `allowed` (trajectory / deputy / `side_effect`
    /// lookups).
    fn tool_named(&self, name: &str) -> Option<ToolHit<'_>>;
    /// `tools.iter().find(|t| t.name == name && t.allowed)` — the
    /// `tools/call` admission pick.
    fn tool_named_allowed(&self, name: &str) -> Option<ToolHit<'_>>;
    /// `tools.iter().any(|t| t.name == name && t.allowed)` —
    /// `checker::tool_is_allowed` for both admission and the
    /// `tools/list` visibility filter.
    fn tool_allowed(&self, name: &str) -> bool;
    /// `tools.iter().any(|t| t.name == name)` — the `listed` bit an
    /// authorization denial reports.
    fn tool_listed(&self, name: &str) -> bool;
}

impl ToolIndex for Policy {
    fn document(&self) -> &Policy {
        self
    }

    fn tool_named(&self, name: &str) -> Option<ToolHit<'_>> {
        self.tools
            .iter()
            .find(|t| t.name == name)
            .map(|tool| ToolHit {
                tool,
                prepared: None,
            })
    }

    fn tool_named_allowed(&self, name: &str) -> Option<ToolHit<'_>> {
        self.tools
            .iter()
            .find(|t| t.name == name && t.allowed)
            .map(|tool| ToolHit {
                tool,
                prepared: None,
            })
    }

    fn tool_allowed(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name && t.allowed)
    }

    fn tool_listed(&self, name: &str) -> bool {
        self.tools.iter().any(|t| t.name == name)
    }
}

impl ToolIndex for PreparedPolicy {
    fn document(&self) -> &Policy {
        &self.policy
    }

    fn tool_named(&self, name: &str) -> Option<ToolHit<'_>> {
        self.slot(name).map(|slot| self.hit(slot.first))
    }

    fn tool_named_allowed(&self, name: &str) -> Option<ToolHit<'_>> {
        self.slot(name)
            .and_then(|slot| slot.first_allowed)
            .map(|i| self.hit(i))
    }

    fn tool_allowed(&self, name: &str) -> bool {
        self.slot(name)
            .is_some_and(|slot| slot.first_allowed.is_some())
    }

    fn tool_listed(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }
}

/// `Arc<PreparedPolicy>` — what the relay's shared state holds —
/// answers like the prepared view it wraps so `&shared.policy` call
/// sites keep working unchanged.
impl<T: ToolIndex + ?Sized> ToolIndex for std::sync::Arc<T> {
    fn document(&self) -> &Policy {
        self.as_ref().document()
    }

    fn tool_named(&self, name: &str) -> Option<ToolHit<'_>> {
        self.as_ref().tool_named(name)
    }

    fn tool_named_allowed(&self, name: &str) -> Option<ToolHit<'_>> {
        self.as_ref().tool_named_allowed(name)
    }

    fn tool_allowed(&self, name: &str) -> bool {
        self.as_ref().tool_allowed(name)
    }

    fn tool_listed(&self, name: &str) -> bool {
        self.as_ref().tool_listed(name)
    }
}

/// `Box<Policy>` / `Box<PreparedPolicy>` callers keep working the way
/// the `&Policy` signatures' deref coercion used to allow: a generic
/// `L: ToolIndex` parameter sees the box itself, so it needs the same
/// pass-through impl `Arc` has.
impl<T: ToolIndex + ?Sized> ToolIndex for Box<T> {
    fn document(&self) -> &Policy {
        self.as_ref().document()
    }

    fn tool_named(&self, name: &str) -> Option<ToolHit<'_>> {
        self.as_ref().tool_named(name)
    }

    fn tool_named_allowed(&self, name: &str) -> Option<ToolHit<'_>> {
        self.as_ref().tool_named_allowed(name)
    }

    fn tool_allowed(&self, name: &str) -> bool {
        self.as_ref().tool_allowed(name)
    }

    fn tool_listed(&self, name: &str) -> bool {
        self.as_ref().tool_listed(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The index reproduces every `iter()` lookup the checkers ran —
    /// bit for bit, including duplicate names where the first entry
    /// wins `find` and the first allowed entry wins admission.
    #[test]
    fn index_matches_the_linear_scans() {
        let mut policy = Policy::default();
        policy.tools.push(ToolPolicy::named("alpha", true));
        // A denied entry wins `find` while admission finds the later
        // allowed duplicate — the first-match asymmetry `iter()`
        // produced over a programmatically built policy.
        policy.tools.push(ToolPolicy::named("beta", false));
        policy.tools.push(ToolPolicy::named("beta", true));
        policy.tools.push(ToolPolicy::named("gamma", false));
        let prepared = PreparedPolicy::new(policy.clone());
        for name in ["alpha", "beta", "gamma", "missing"] {
            assert_eq!(
                policy.tool_listed(name),
                prepared.tool_listed(name),
                "listed: {name}"
            );
            assert_eq!(
                policy.tool_allowed(name),
                prepared.tool_allowed(name),
                "allowed: {name}"
            );
            assert_eq!(
                policy.tool_named(name).map(|h| h.tool),
                prepared.tool_named(name).map(|h| h.tool),
                "find: {name}"
            );
            assert_eq!(
                policy.tool_named_allowed(name).map(|h| h.tool),
                prepared.tool_named_allowed(name).map(|h| h.tool),
                "find allowed: {name}"
            );
        }
        // "beta": `find` picks the denied first entry, admission picks
        // the allowed duplicate — both preserved.
        assert!(!prepared.tool_named("beta").unwrap().tool.allowed);
        assert!(prepared.tool_named_allowed("beta").unwrap().tool.allowed);
        // The shared `Arc` wrapper answers identically.
        let shared = std::sync::Arc::new(PreparedPolicy::new(policy.clone()));
        assert!(shared.tool_allowed("beta"));
        assert!(!shared.tool_allowed("gamma"));
        assert!(shared.tool_listed("gamma"));
        assert!(!shared.tool_listed("missing"));
    }

    /// The prepared per-tool rules match what the request path derived
    /// per call — the opaque matcher, parsed `side_effect`, and
    /// resolved `inputResponses` mode.
    #[test]
    fn prepared_tools_match_per_call_derivation() {
        let mut tool = ToolPolicy::named("memo", true);
        tool.opaque_fields = vec![super::super::opaque::OpaqueField::parse("note").unwrap()];
        tool.side_effect = Some("read_only".to_string());
        let mut policy = Policy::default();
        policy.tools.push(tool);
        policy.tools.push(ToolPolicy::named("plain", true));
        let prepared = PreparedPolicy::new(policy.clone());

        let hit = prepared.tool_named("memo").unwrap();
        let prepared_tool = hit.prepared.expect("prepared view carries rules");
        assert!(prepared_tool.opaque.is_some());
        assert_eq!(hit.side_effect(), Some(SideEffect::ReadOnly));
        assert_eq!(
            hit.resolved_input_responses(),
            policy.tools[0]
                .input_responses
                .resolve(policy.tools[0].has_security_contract())
        );

        let plain = prepared.tool_named("plain").unwrap();
        assert!(plain.prepared.unwrap().opaque.is_none());
        assert_eq!(plain.side_effect(), None);

        // The bare `Policy` view returns the same side_effect /
        // inputResponses answers — derived per call, as before.
        let lin = policy.tool_named("memo").unwrap();
        assert!(lin.prepared.is_none());
        assert_eq!(lin.side_effect(), hit.side_effect());
        assert_eq!(
            lin.resolved_input_responses(),
            hit.resolved_input_responses()
        );
    }

    /// The wrapped document reads identical bytes through `Deref` —
    /// KDL export, hash inputs, and server identity are untouched.
    #[test]
    fn document_forms_are_untouched() {
        let mut policy = Policy::default();
        policy.tools.push({
            let mut t = ToolPolicy::named("t", true);
            t.server = Some("srv".to_string());
            t
        });
        let prepared = PreparedPolicy::new(policy.clone());
        assert_eq!(prepared.document(), &policy);
        assert_eq!(prepared.to_kdl(), policy.to_kdl());
        assert_eq!(prepared.declared_servers(), policy.declared_servers());
    }
}
