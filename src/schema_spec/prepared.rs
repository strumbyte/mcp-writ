//! RF05b — the reusable prepared form of an `args_schema` document.
//!
//! The policy document still carries the schema text (KDL emission,
//! the effective hash, and provenance read it exactly as before).
//! What a session shares is this execution form, built once where the
//! tool set becomes final:
//!
//! - The schema is parsed once into [`RawJsonOwned`] — previously
//!   `validate_arguments` reparsed the text on every request.
//! - Each local `$ref` target resolves through a memoized index into
//!   the parsed document's values. Resolution is a pure function of
//!   the schema and the target string, so the cached answer is the
//!   same value — and the same failure — the pointer walk produced.
//!   Cycles stay index entries; nothing is expanded recursively.
//! - Each `pattern` string compiles once, on first use, deduplicated
//!   across the schema. Compilation is deferred to the moment
//!   evaluation reaches the pattern — never at prepare time — so an
//!   invalid pattern in an unreached branch keeps failing (or not
//!   failing) exactly as before, and a reached one produces the same
//!   `Fatal` the per-request compile emitted.
//!
//! Everything request-scoped stays per call: the evaluator still
//! draws fresh branch/node budgets and walks the instance, so sharing
//! this structure across inputs cannot reuse a verdict. The caches
//! hold only facts derived from the schema alone.
//!
//! Bounds: building consumes `schema_text` bytes and retains one
//! document (text plus one index entry per JSON node) — O(input
//! bytes), the same order the per-request parse materialized
//! transiently. Cache growth is bounded by the schema itself: at most
//! one entry per distinct `$ref` string and per distinct `pattern`
//! string, each O(key bytes). No new acceptance limit is introduced —
//! a schema the old path accepted still builds (even an invalid-JSON
//! one, which simply stores its parse error instead of failing
//! closed at prepare).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use nojson::{RawJsonOwned, RawJsonValue};

/// The outcome a `$ref` slot caches: the target's index inside the
/// prepared document's value array, or the resolution failure text
/// verbatim from `resolve_local_ref`.
type RefOutcome = Result<usize, Box<str>>;

/// The outcome a `pattern` slot caches: the compiled regex shared as
/// an `Arc` so evaluation runs outside the interning lock, or the
/// compile error text for the evaluator to place in its `Fatal`.
type PatternOutcome = Result<Arc<regex_lite::Regex>, Box<str>>;

/// Heap a filled outcome retains beyond its `OnceLock` slot shell —
/// the deterministic-estimate convention `estimated_resident_bytes`
/// documents: error texts count in full; a compiled `Regex` counts
/// its `Arc` target allocation (`size_of`), while regex_lite's
/// internal program heap is an opaque detail of that crate.
#[cfg(feature = "measure")]
trait OutcomeBytes {
    fn outcome_bytes(&self) -> u64;
}

#[cfg(feature = "measure")]
impl OutcomeBytes for RefOutcome {
    fn outcome_bytes(&self) -> u64 {
        match self {
            Ok(_) => 0,
            Err(text) => text.len() as u64,
        }
    }
}

#[cfg(feature = "measure")]
impl OutcomeBytes for PatternOutcome {
    fn outcome_bytes(&self) -> u64 {
        match self {
            Ok(_) => std::mem::size_of::<regex_lite::Regex>() as u64,
            Err(text) => text.len() as u64,
        }
    }
}

/// Lazily filled, once-per-distinct-string cache slots shared by the
/// `$ref` and `pattern` tables. `OnceLock` gives one build per entry
/// under concurrent first requests — waiters block on the in-flight
/// build rather than duplicating it.
#[derive(Debug)]
struct LazyTable<V> {
    map: Mutex<HashMap<Box<str>, Arc<OnceLock<V>>>>,
}

impl<V> LazyTable<V> {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// The slot for `key` — created empty on first sight.
    fn intern(&self, key: &str) -> Arc<OnceLock<V>> {
        let mut map = self.map.lock().unwrap();
        match map.get(key) {
            Some(slot) => slot.clone(),
            None => {
                let slot: Arc<OnceLock<V>> = Arc::new(OnceLock::new());
                map.insert(key.into(), slot.clone());
                slot
            }
        }
    }

    /// Entries interned so far — the test-side dedup assertion.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[cfg(feature = "measure")]
impl<V: OutcomeBytes> LazyTable<V> {
    /// Capacity-based estimate of the bytes the table owns — the map
    /// itself, each interned key and its `OnceLock` slot, plus the
    /// heap each filled outcome retains (`OutcomeBytes`).
    fn resident_bytes(&self) -> u64 {
        // `Arc<OnceLock<V>>` is a fat-word-free pointer; the slot tuple
        // size is `V`-independent, so one constant fits both tables.
        const SLOT_BYTES: u64 = std::mem::size_of::<(Box<str>, Arc<OnceLock<()>>)>() as u64 + 1;
        let map = self.map.lock().unwrap();
        let mut n = map.capacity() as u64 * SLOT_BYTES;
        n += map.keys().map(|k| k.len() as u64).sum::<u64>();
        n += (map.len() * std::mem::size_of::<OnceLock<V>>()) as u64;
        n += map
            .values()
            .filter_map(|slot| slot.get())
            .map(OutcomeBytes::outcome_bytes)
            .sum::<u64>();
        n
    }
}

/// A parsed `args_schema` plus its schema-only memo tables — see the
/// module docs for the semantics contract.
#[derive(Debug)]
pub struct PreparedSchema {
    /// The parsed document, or the error message the old
    /// parse-per-request path produced (`"invalid args_schema JSON:
    /// {e}"`), stored verbatim so an invalid schema keeps failing at
    /// evaluation instead of becoming a new prepare-time refusal.
    doc: Result<RawJsonOwned, Box<str>>,
    refs: LazyTable<RefOutcome>,
    patterns: LazyTable<PatternOutcome>,
}

impl PreparedSchema {
    /// Parse `schema_text` once. The parse consumes the same input the
    /// old per-request `RawJson::parse` did and produces the same
    /// error on the same text — an invalid document stores its message
    /// rather than failing the build.
    pub fn new(schema_text: String) -> Self {
        #[cfg(feature = "measure")]
        {
            crate::measure::incr(&crate::measure::SCHEMA_PREPARED_BUILDS, 1);
            crate::measure::incr(&crate::measure::SCHEMA_PARSE_CALLS, 1);
        }
        let doc = match RawJsonOwned::parse(schema_text) {
            Ok(doc) => Ok(doc),
            Err(e) => Err(format!("invalid args_schema JSON: {e}").into()),
        };
        Self {
            doc,
            refs: LazyTable::new(),
            patterns: LazyTable::new(),
        }
    }

    /// The schema root — `None` only when the document failed to
    /// parse, in which case [`Self::parse_error`] holds the message.
    pub fn root(&self) -> Option<RawJsonValue<'_, '_>> {
        self.doc.as_ref().ok().map(|d| d.value())
    }

    /// The stored `"invalid args_schema JSON: …"` message for a
    /// document that failed to parse — `None` for a parsed one.
    pub fn parse_error(&self) -> Option<&str> {
        self.doc.as_ref().err().map(|e| &**e)
    }

    /// `resolve_local_ref` on this document, memoized per `target`
    /// string — the same resolved value and the same failure text the
    /// uncached walk produced, since both are pure functions of the
    /// schema. The resolved node is returned as a fresh borrow on
    /// every call; only its stable index is cached.
    pub(crate) fn resolve_local(&self, target: &str) -> Result<RawJsonValue<'_, '_>, String> {
        let doc = self
            .doc
            .as_ref()
            .expect("evaluator resolves refs only on a parsed schema");
        let slot = self.refs.intern(target);
        let outcome = slot.get_or_init(|| {
            super::resolve_local_ref(doc.value(), target)
                .map(|v| v.index())
                .map_err(Box::from)
        });
        match outcome {
            Ok(index) => Ok(doc
                .get_value_by_index(*index)
                .expect("the cached index names a value in this document")),
            Err(e) => Err(e.to_string()),
        }
    }

    /// `regex_lite::Regex::new(pat)` — built once on first use and
    /// shared by every schema node spelling this pattern. The compile
    /// error is cached too and returned for the evaluator to place in
    /// its `Fatal` — identical text to the per-request compile path.
    pub(crate) fn compiled_pattern(&self, pat: &str) -> Result<Arc<regex_lite::Regex>, String> {
        let slot = self.patterns.intern(pat);
        let outcome = slot.get_or_init(|| {
            #[cfg(feature = "measure")]
            crate::measure::incr(&crate::measure::SCHEMA_REGEX_BUILDS, 1);
            regex_lite::Regex::new(pat)
                .map(Arc::new)
                .map_err(|e| e.to_string().into())
        });
        match outcome {
            Ok(re) => Ok(re.clone()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Entries interned so far — tests assert the caches dedupe.
    #[cfg(test)]
    pub(crate) fn interned_counts(&self) -> (usize, usize) {
        (self.refs.len(), self.patterns.len())
    }

    /// Capacity-based estimate of the bytes this form owns — the
    /// resident cost a session pays for the reusable document and
    /// caches. Deterministic structural accounting, not an allocator
    /// reading (same convention as `PreparedPolicy`'s estimate): the
    /// value-array entries are counted exactly, while their per-entry
    /// size uses the documented `JsonValueIndexEntry` layout estimate
    /// since the crate keeps the type private.
    #[cfg(feature = "measure")]
    #[doc(hidden)]
    pub fn estimated_resident_bytes(&self) -> u64 {
        let mut n = std::mem::size_of::<Self>() as u64;
        if let Ok(doc) = &self.doc {
            n += doc.text().len() as u64;
            // `JsonValueIndexEntry` is `{kind, escaped, text: Range<usize>,
            // end_index: usize}` — two `usize`s plus the value index and
            // the small discriminant/bool, aligned to a word.
            const VALUE_ENTRY_BYTES_EST: u64 = 32;
            let mut count = 0u64;
            while doc.get_value_by_index(count as usize).is_some() {
                count += 1;
            }
            n += count * VALUE_ENTRY_BYTES_EST;
        }
        n += self.refs.resident_bytes() + self.patterns.resident_bytes();
        n
    }
}
