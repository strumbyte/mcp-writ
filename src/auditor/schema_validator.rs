//! Args-schema validation for tool calls
//!
//! Validates `params.arguments` in `tools/call` requests against the
//! `args_schema` configured in the policy (which is the MCP server's
//! `input_schema` — JSON Schema format).
//!
//! The supported dialect is declared once in `crate::schema_spec`:
//! JSON Schema 2020-12 keywords the evaluator implements (`type`,
//! `properties`, `required`, `additionalProperties`, `items`, `enum`,
//! `const`, the `anyOf`/`oneOf`/`allOf` combinators, numeric and string
//! bounds, `minItems`/`maxItems`/`uniqueItems`, `multipleOf`, local `$ref`)
//! plus annotation keywords (`format`, `description`, `title`, `default`,
//! `examples`, `$schema`, `$id`, `$comment`, `definitions`, `$defs`).
//! `format` is annotation-only per the 2020-12 spec — accepted, never
//! enforced. Anything else is rejected so an unenforceable schema fails
//! closed at the proxy instead of silently passing.
//!
//! `args_schema` applies only to `params.arguments`. The sibling
//! `params.inputResponses` field (MRTR) is intentionally not covered —
//! see `check_request` for its deny-by-default handling.
//!
//! RF05b: the schema JSON is evaluated through
//! [`crate::schema_spec::prepared::PreparedSchema`] — a parse-once
//! document with lazily memoized `$ref` resolutions and `pattern`
//! compilations. The evaluator below keeps its order, errors, and
//! per-call budgets; only the document it walks and the two
//! schema-derived lookups moved behind the prepared form.

use std::cmp::Ordering;
use std::collections::HashSet;

use nojson::{JsonValueKind, RawJsonValue};

use crate::schema_spec::prepared::PreparedSchema;
use crate::schema_spec::{
    MAX_SCHEMA_DEPTH, VALID_TYPES, check_unsupported_keywords, field_path, member_opt, str_val,
};

mod decimal;

use decimal::{ExactDecimal, compare_numeric_strings, is_multiple_of, numbers_equal};

/// Combinator/`$ref` branch evaluations allowed per call. Bounds the
/// fan-out `anyOf`/`oneOf`/`allOf`/`$ref` add on top of plain structural
/// validation — a hostile schema (deep `$ref` chains, nested combinators)
/// is rejected before it can amplify per-call cost. Input-driven
/// traversal (`properties`/`items`) does not consume this budget — it is
/// capped separately by [`MAX_NODE_EVALS`].
const MAX_BRANCH_EVALS: usize = 1 << 20;

/// Per-call input-node visits: one per `validate_value` call plus each
/// input member traversed. Every combinator/`$ref` branch re-walks the
/// input subtree, so the frame-size limit alone leaves a multiplicative
/// blow-up (input nodes × branch evaluations); this caps the product
/// while staying far above legitimate call shapes.
const MAX_NODE_EVALS: usize = 1 << 24;
/// Why resolving an `args_schema` reference failed. The out-of-tree
/// `@path` case is its own variant so the checker can label the audit
/// event `validation.path_traversal` without re-reading the message —
/// a schema-side answer, decided where the refusal is produced.
#[derive(Debug)]
pub enum SchemaRefError {
    /// The `@path` canonicalized outside the working directory.
    PathTraversal(String),
    /// Missing file, read/I/O failure, non-UTF-8 content, or a
    /// working-directory lookup failure.
    Other(String),
}

impl SchemaRefError {
    /// The refusal text as audit records and the wire spell it.
    pub fn reason(&self) -> &str {
        match self {
            Self::PathTraversal(r) | Self::Other(r) => r,
        }
    }

    /// Consume the error into its refusal text.
    pub fn into_reason(self) -> String {
        match self {
            Self::PathTraversal(r) | Self::Other(r) => r,
        }
    }
}

impl std::fmt::Display for SchemaRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for SchemaRefError {}

/// Resolve an args_schema reference to a JSON schema string.
///
/// - If the reference starts with `@`, the rest is treated as a file path.
/// - Otherwise, it is treated as inline JSON.
pub fn resolve_schema(schema_ref: &str) -> Result<String, SchemaRefError> {
    if let Some(path) = schema_ref.strip_prefix('@') {
        let path = path.trim();

        // Canonicalize the path to resolve symlinks and `..` components,
        // then verify the result lives under the current working directory.
        let canonical = std::fs::canonicalize(path).map_err(|e| {
            SchemaRefError::Other(if e.kind() == std::io::ErrorKind::NotFound {
                format!("failed to read schema file '{path}': {e}")
            } else {
                format!("failed to resolve schema file path '{path}': {e}")
            })
        })?;
        let base_raw = std::env::current_dir().map_err(|e| {
            SchemaRefError::Other(format!("failed to determine working directory: {e}"))
        })?;
        let base = std::fs::canonicalize(&base_raw).unwrap_or(base_raw);
        if !canonical.starts_with(&base) {
            return Err(SchemaRefError::PathTraversal(format!(
                "path traversal: schema file '{}' resolves outside the working directory",
                canonical.display(),
            )));
        }

        // Bind the read to the containment check: the opened handle is
        // the same object whose real path must stay under `base` — a
        // component swapped for a link after canonicalization fails the
        // handle-side proof instead of serving out-of-tree bytes.
        let root = crate::fspriv::canonical_root(&base).map_err(|e| {
            SchemaRefError::Other(format!("failed to resolve schema file path '{path}': {e}"))
        })?;
        let bytes = crate::fspriv::read_no_follow_bounded_in(
            &canonical,
            crate::policy::MAX_SCHEMA_FILE_BYTES,
            &root,
        )
        .map_err(|e| SchemaRefError::Other(format!("failed to read schema file '{path}': {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| SchemaRefError::Other(format!("failed to read schema file '{path}': {e}")))
    } else {
        Ok(schema_ref.to_string())
    }
}

/// Validate tool arguments against a JSON Schema string.
///
/// Returns `Ok(())` if the arguments satisfy the schema, or `Err` with a
/// human-readable description of the first violation found.
///
/// This entry prepares a fresh [`PreparedSchema`] per call — the same
/// per-request parse the bare `&Policy` check path always did. Prepared
/// sessions route through [`validate_prepared`] instead, which shares
/// one document and its `$ref`/`pattern` memos across requests.
pub fn validate_arguments(arguments: RawJsonValue<'_, '_>, schema_str: &str) -> Result<(), String> {
    let schema = PreparedSchema::new(schema_str.to_string());
    validate_prepared(arguments, &schema)
}

/// The per-request evaluation entry — same verdicts, error order, and
/// budgets whether `schema` was just built for this call or has served
/// the session for a while. A schema whose text failed to parse stores
/// its parse error and returns it here on every call, matching the old
/// parse-then-fail path byte for byte.
pub(crate) fn validate_prepared(
    arguments: RawJsonValue<'_, '_>,
    schema: &PreparedSchema,
) -> Result<(), String> {
    if let Some(msg) = schema.parse_error() {
        return Err(msg.to_string());
    }
    let root = schema.root().expect("parsed schema has a root value");
    let mut eval = Eval {
        schema,
        branch_budget: MAX_BRANCH_EVALS,
        node_budget: MAX_NODE_EVALS,
    };
    validate_value(arguments, root, "", 0, &mut eval).map_err(EvalError::into_message)
}

// ---------------------------------------------------------------------------
// Core recursive validator
// ---------------------------------------------------------------------------

/// Per-call evaluator state carried through the recursion. The
/// prepared schema is shared across calls — `branch_budget` and
/// `node_budget` are drawn fresh here every call, so a shared document
/// never carries spent budget (or a verdict) between requests.
struct Eval<'s> {
    /// The prepared schema being evaluated — `$ref` targets and
    /// `pattern` regexes are resolved/compiled through its memos.
    schema: &'s PreparedSchema,
    /// Combinator/`$ref` branch evaluations remaining.
    branch_budget: usize,
    /// `validate_value` calls and input members visited remaining.
    node_budget: usize,
}

/// Why an evaluation failed. `Mismatch` is the instance failing the
/// schema — `anyOf`/`oneOf` may count it as a non-match and try another
/// branch. `Fatal` is a malformed schema or a resource limit — it can
/// never be a non-match, so combinators propagate it: a broken `oneOf`
/// branch must not pass silently because a sibling happened to match.
enum EvalError {
    Mismatch(String),
    Fatal(String),
}

impl EvalError {
    /// Wrap a foreign error (nojson parse errors, `String` messages) as
    /// fatal — it means the schema or the runtime failed, not that the
    /// instance failed the schema.
    fn fatal(e: impl std::fmt::Display) -> Self {
        Self::Fatal(e.to_string())
    }

    fn into_message(self) -> String {
        match self {
            Self::Mismatch(m) | Self::Fatal(m) => m,
        }
    }
}

/// Spend one unit of a per-call evaluation budget, failing closed when
/// it is exhausted. `what`/`limit` name the budget in the message.
fn spend(budget: &mut usize, limit: usize, what: &str, path: &str) -> Result<(), EvalError> {
    if *budget == 0 {
        let p = if path.is_empty() { "schema" } else { path };
        return Err(EvalError::Fatal(format!(
            "at '{p}': schema {what} evaluation limit {limit} exceeded"
        )));
    }
    *budget -= 1;
    Ok(())
}

fn spend_branch(eval: &mut Eval<'_>, path: &str) -> Result<(), EvalError> {
    spend(
        &mut eval.branch_budget,
        MAX_BRANCH_EVALS,
        "combinator",
        path,
    )
}

fn spend_node(eval: &mut Eval<'_>, path: &str) -> Result<(), EvalError> {
    spend(&mut eval.node_budget, MAX_NODE_EVALS, "node", path)
}

fn validate_value(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
    depth: u32,
    eval: &mut Eval<'_>,
) -> Result<(), EvalError> {
    spend_node(eval, path)?;
    if depth > MAX_SCHEMA_DEPTH {
        let p = if path.is_empty() { "schema" } else { path };
        return Err(EvalError::Fatal(format!(
            "at '{p}': schema evaluation exceeds depth limit {MAX_SCHEMA_DEPTH}"
        )));
    }

    // Boolean schema handling (JSON Schema 2020-12 §4.3.2)
    // "A boolean schema is a schema which is either the boolean value true or false.
    // The schema true always validates successfully; the schema false always fails to validate."
    match schema.kind() {
        JsonValueKind::Boolean => {
            if schema.as_boolean_str().map_err(EvalError::fatal)? == "true" {
                return Ok(());
            } else {
                let p = if path.is_empty() { "value" } else { path };
                return Err(EvalError::Mismatch(format!(
                    "at '{p}': schema is false, value rejected"
                )));
            }
        }
        JsonValueKind::Object => {}
        _ => {
            let p = if path.is_empty() { "schema" } else { path };
            return Err(EvalError::Fatal(format!(
                "at '{p}': schema must be a boolean or an object"
            )));
        }
    }

    // 0. Check for unsupported schema keywords
    check_unsupported_keywords(schema, path).map_err(EvalError::Fatal)?;

    // `$ref` (2020-12): evaluated alongside its siblings. Same-document
    // targets only — `#` or `#/<json-pointer>`; external references are
    // unsupported and fail closed.
    if let Some(ref_val) = member_opt(schema, "$ref") {
        let target = str_val(ref_val).map_err(EvalError::Fatal)?;
        let resolved = eval
            .schema
            .resolve_local(&target)
            .map_err(EvalError::Fatal)?;
        spend_branch(eval, path)?;
        validate_value(value, resolved, path, depth + 1, eval)?;
    }

    // 1. Check "type" constraint — scalar name or an array of alternatives.
    if let Some(type_val) = member_opt(schema, "type") {
        match type_val.kind() {
            JsonValueKind::String => {
                check_type(value, &str_val(type_val).map_err(EvalError::Fatal)?, path)?;
            }
            JsonValueKind::Array => {
                let mut names = Vec::new();
                for t in type_val.to_array().map_err(EvalError::fatal)? {
                    if t.kind() != JsonValueKind::String {
                        return Err(EvalError::Fatal(format!(
                            "at '{}': type array elements must be strings",
                            if path.is_empty() { "schema" } else { path }
                        )));
                    }
                    names.push(str_val(t).map_err(EvalError::Fatal)?);
                }
                if names.is_empty() {
                    return Err(EvalError::Fatal(format!(
                        "at '{}': type array must not be empty",
                        if path.is_empty() { "schema" } else { path }
                    )));
                }
                // An unknown alternative makes the union malformed even
                // when an earlier member matches — the load-time scan
                // rejects the same shape, so the evaluator must too.
                for name in &names {
                    if !VALID_TYPES.contains(&name.as_ref()) {
                        return Err(EvalError::Fatal(format!("unknown schema type '{name}'")));
                    }
                }
                let mut matched = false;
                for name in &names {
                    if type_matches(value, name)? {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    let field = if path.is_empty() { "value" } else { path };
                    let actual = kind_name(value.kind());
                    return Err(EvalError::Mismatch(format!(
                        "at '{field}': should be one of [{}], got {actual}",
                        names.join(", ")
                    )));
                }
            }
            _ => {
                return Err(EvalError::Fatal(format!(
                    "at '{}': type must be a string or an array of type names",
                    if path.is_empty() { "schema" } else { path }
                )));
            }
        }
    }

    // 2. Check "enum" constraint
    if let Some(enum_val) = member_opt(schema, "enum") {
        check_enum(value, enum_val, path)?;
    }

    // 3. Check "const" — same equality semantics as `enum`.
    if let Some(const_val) = member_opt(schema, "const")
        && !json_values_equal(value, const_val)
    {
        let field = if path.is_empty() { "value" } else { path };
        return Err(EvalError::Mismatch(format!(
            "at '{field}': value {} is not equal to const {}",
            value.as_raw_str(),
            const_val.as_raw_str()
        )));
    }

    // 4. Numeric constraints (minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf)
    check_numeric_constraints(value, schema, path)?;

    // 5. String constraints (minLength, maxLength, pattern)
    check_string_constraints(value, schema, path, eval)?;

    // 6. Object-specific: required, properties, additionalProperties
    if value.kind() == JsonValueKind::Object {
        validate_object(value, schema, path, depth, eval)?;
    }

    // 7. Array-specific: items, minItems, maxItems, uniqueItems
    if value.kind() == JsonValueKind::Array {
        validate_array(value, schema, path, depth, eval)?;
    }

    // 8. Combinators — conjunctive semantics, so the order among them does
    //    not change the verdict. `allOf` requires every branch, `anyOf`
    //    at least one, `oneOf` exactly one.
    if let Some(all_of) = member_opt(schema, "allOf") {
        for branch in combinator_branches(all_of, "allOf", path)? {
            spend_branch(eval, path)?;
            validate_value(value, branch, path, depth + 1, eval)?;
        }
    }
    if let Some(any_of) = member_opt(schema, "anyOf") {
        let branches = combinator_branches(any_of, "anyOf", path)?;
        let mut first_err: Option<String> = None;
        let mut matched = false;
        // No early exit on a match — remaining branches are evaluated so a
        // fatal schema error behind the matching branch still surfaces
        // instead of passing under it (bounded by `branch_budget`).
        for branch in branches {
            spend_branch(eval, path)?;
            match validate_value(value, branch, path, depth + 1, eval) {
                Ok(()) => matched = true,
                Err(EvalError::Mismatch(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(fatal @ EvalError::Fatal(_)) => return Err(fatal),
            }
        }
        if !matched {
            let field = if path.is_empty() { "value" } else { path };
            return Err(EvalError::Mismatch(format!(
                "at '{field}': value does not match any anyOf branch ({})",
                first_err.unwrap_or_default()
            )));
        }
    }
    if let Some(one_of) = member_opt(schema, "oneOf") {
        let branches = combinator_branches(one_of, "oneOf", path)?;
        let mut matches = 0usize;
        // No early exit once the count is decided — remaining branches are
        // evaluated so a fatal schema error behind them still surfaces
        // (bounded by `branch_budget`), and the count stays accurate.
        for branch in branches {
            spend_branch(eval, path)?;
            match validate_value(value, branch, path, depth + 1, eval) {
                Ok(()) => matches += 1,
                Err(EvalError::Mismatch(_)) => {}
                Err(fatal @ EvalError::Fatal(_)) => return Err(fatal),
            }
        }
        if matches != 1 {
            let field = if path.is_empty() { "value" } else { path };
            return Err(EvalError::Mismatch(format!(
                "at '{field}': value matches {matches} oneOf branches, expected exactly 1"
            )));
        }
    }

    Ok(())
}

/// The subschemas an `anyOf`/`oneOf`/`allOf` keyword carries — JSON
/// Schema requires a non-empty array.
fn combinator_branches<'t, 'r>(
    val: RawJsonValue<'t, 'r>,
    name: &str,
    path: &str,
) -> Result<Vec<RawJsonValue<'t, 'r>>, EvalError> {
    let p = if path.is_empty() { "schema" } else { path };
    let branches: Vec<_> = match val.kind() {
        JsonValueKind::Array => val.to_array().map_err(EvalError::fatal)?.collect(),
        _ => Vec::new(),
    };
    if branches.is_empty() {
        return Err(EvalError::Fatal(format!(
            "at '{p}': '{name}' must be a non-empty array of schemas"
        )));
    }
    Ok(branches)
}

fn check_enum(
    value: RawJsonValue<'_, '_>,
    enum_val: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), EvalError> {
    let items = enum_val
        .to_array()
        .map_err(|e| EvalError::Fatal(format!("at '{path}': enum must be an array: {e}")))?;
    let mut matched = false;
    for item in items {
        if json_values_equal(value, item) {
            matched = true;
            break;
        }
    }
    if !matched {
        let field = if path.is_empty() { "value" } else { path };
        let val_raw = value.as_raw_str();
        return Err(EvalError::Mismatch(format!(
            "at '{field}': value {val_raw} is not in enum"
        )));
    }
    Ok(())
}

/// JSON Schema value equality: objects compare without regard to member
/// order and numbers compare by exact decimal value — `-0.0` equals `0`,
/// and `{a:1,b:2}` equals `{b:2,a:1}`. Both `enum`/`const` membership and
/// `uniqueItems` (via [`canonical_key`]) share these semantics.
fn json_values_equal(a: RawJsonValue<'_, '_>, b: RawJsonValue<'_, '_>) -> bool {
    if a.kind().is_number() && b.kind().is_number() {
        if let (Ok(na), Ok(nb)) = (a.as_number_str(), b.as_number_str()) {
            return numbers_equal(na, nb);
        }
        return false;
    }
    if a.kind() != b.kind() {
        return false;
    }
    match a.kind() {
        JsonValueKind::Null => true,
        JsonValueKind::Boolean => a.as_boolean_str().ok() == b.as_boolean_str().ok(),
        JsonValueKind::String => {
            let sa = a.to_unquoted_string_str().ok();
            let sb = b.to_unquoted_string_str().ok();
            match (sa, sb) {
                (Some(va), Some(vb)) => va == vb,
                _ => false,
            }
        }
        JsonValueKind::Array => {
            let a_items = a.to_array().into_iter().flatten();
            let b_items: Vec<_> = match b.to_array() {
                Ok(it) => it.collect(),
                Err(_) => return false,
            };
            let a_items: Vec<_> = a_items.collect();
            if a_items.len() != b_items.len() {
                return false;
            }
            a_items
                .iter()
                .zip(b_items.iter())
                .all(|(x, y)| json_values_equal(*x, *y))
        }
        JsonValueKind::Object => {
            let Ok(a_members) = a.to_object() else {
                return false;
            };
            let Ok(b_members) = b.to_object() else {
                return false;
            };
            let a_map: Vec<_> = a_members
                .filter_map(|(k, v)| str_val(k).ok().map(|n| (n.into_owned(), v)))
                .collect();
            let b_map: Vec<_> = b_members
                .filter_map(|(k, v)| str_val(k).ok().map(|n| (n.into_owned(), v)))
                .collect();
            if a_map.len() != b_map.len() {
                return false;
            }
            a_map.iter().all(|(name, av)| {
                b_map
                    .iter()
                    .find(|(bn, _)| bn == name)
                    .is_some_and(|(_, bv)| json_values_equal(*av, *bv))
            })
        }
        _ => a.as_raw_str().trim() == b.as_raw_str().trim(),
    }
}

fn check_numeric_constraints(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), EvalError> {
    if !value.kind().is_number() {
        return Ok(());
    }
    let num_str = value.as_number_str().map_err(EvalError::fatal)?;
    let field = if path.is_empty() { "value" } else { path };

    if let Some(min_val) = member_opt(schema, "minimum") {
        let min_s = min_val.as_number_str().map_err(EvalError::fatal)?;
        if compare_numeric_strings(num_str, min_s).map_err(EvalError::Fatal)? == Ordering::Less {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': {num_str} is less than minimum {min_s}"
            )));
        }
    }
    if let Some(max_val) = member_opt(schema, "maximum") {
        let max_s = max_val.as_number_str().map_err(EvalError::fatal)?;
        if compare_numeric_strings(num_str, max_s).map_err(EvalError::Fatal)? == Ordering::Greater {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': {num_str} is greater than maximum {max_s}"
            )));
        }
    }
    if let Some(ex_min_val) = member_opt(schema, "exclusiveMinimum") {
        let ex_min_s = ex_min_val.as_number_str().map_err(EvalError::fatal)?;
        let cmp = compare_numeric_strings(num_str, ex_min_s).map_err(EvalError::Fatal)?;
        if cmp == Ordering::Less || cmp == Ordering::Equal {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': {num_str} is less than or equal to exclusiveMinimum {ex_min_s}"
            )));
        }
    }
    if let Some(ex_max_val) = member_opt(schema, "exclusiveMaximum") {
        let ex_max_s = ex_max_val.as_number_str().map_err(EvalError::fatal)?;
        let cmp = compare_numeric_strings(num_str, ex_max_s).map_err(EvalError::Fatal)?;
        if cmp == Ordering::Greater || cmp == Ordering::Equal {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': {num_str} is greater than or equal to exclusiveMaximum {ex_max_s}"
            )));
        }
    }

    // `multipleOf`: v % d == 0 on exact decimal significands — no float
    // rounding, so `0.3 % 0.1 == 0` holds as the spec requires.
    if let Some(mo_val) = member_opt(schema, "multipleOf") {
        let mo_s = mo_val.as_number_str().map_err(EvalError::fatal)?;
        if !is_multiple_of(num_str, mo_s)? {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': {num_str} is not a multiple of {mo_s}"
            )));
        }
    }
    Ok(())
}

fn check_string_constraints(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
    eval: &Eval<'_>,
) -> Result<(), EvalError> {
    if value.kind() != JsonValueKind::String {
        return Ok(());
    }
    let s = str_val(value).map_err(EvalError::fatal)?;
    let char_count = s.chars().count();
    let field = if path.is_empty() { "value" } else { path };

    if let Some(min_val) = member_opt(schema, "minLength") {
        let min_s = min_val.as_integer_str().map_err(EvalError::fatal)?;
        let min: usize = min_s
            .parse()
            .map_err(|_| EvalError::Fatal(format!("invalid minLength '{min_s}'")))?;
        if char_count < min {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': string length {char_count} is less than minLength {min}"
            )));
        }
    }
    if let Some(max_val) = member_opt(schema, "maxLength") {
        let max_s = max_val.as_integer_str().map_err(EvalError::fatal)?;
        let max: usize = max_s
            .parse()
            .map_err(|_| EvalError::Fatal(format!("invalid maxLength '{max_s}'")))?;
        if char_count > max {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': string length {char_count} is greater than maxLength {max}"
            )));
        }
    }
    if let Some(pat_val) = member_opt(schema, "pattern") {
        let pat_s = str_val(pat_val).map_err(EvalError::fatal)?;
        // Compiled once per prepared schema per distinct pattern —
        // the same `Fatal` text the per-request `Regex::new` produced.
        let re = eval.schema.compiled_pattern(&pat_s).map_err(|e| {
            EvalError::Fatal(format!(
                "at '{field}': invalid regex pattern '{pat_s}': {e}"
            ))
        })?;
        if !re.is_match(&s) {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': string does not match pattern '{pat_s}'"
            )));
        }
    }
    Ok(())
}

fn validate_object(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
    depth: u32,
    eval: &mut Eval<'_>,
) -> Result<(), EvalError> {
    // Collect all (key, value) entries in a single pass (avoids double iteration).
    // Members count against the node budget: every combinator branch
    // re-collects them, so per-member cost must be charged like a call.
    let mut entries: Vec<(String, RawJsonValue<'_, '_>)> = Vec::new();
    for (key, val) in value.to_object().map_err(EvalError::fatal)? {
        spend_node(eval, path)?;
        entries.push((str_val(key).map_err(EvalError::fatal)?.into_owned(), val));
    }

    // --- required -----------------------------------------------------------
    if let Some(required_val) = member_opt(schema, "required") {
        // Member names as a lookup set: rescanning `entries` per required
        // name is O(required × entries) per call — a multiplicative
        // blow-up on wide inputs under combinators.
        let present: HashSet<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        for req in required_val.to_array().map_err(EvalError::fatal)? {
            let name = str_val(req).map_err(EvalError::fatal)?;
            if !present.contains(&*name) {
                return Err(EvalError::Mismatch(format!(
                    "at '{}': missing required field",
                    field_path(path, &name)
                )));
            }
        }
    }

    // --- properties & additionalProperties ----------------------------------
    let properties = member_opt(schema, "properties");
    let additional_props = member_opt(schema, "additionalProperties");

    // additionalProperties can be: boolean true/false, a schema object, or absent.
    // - absent / true  → allow all extra keys without validation
    // - false          → reject any extra keys
    // - schema object  → validate each extra key's value against the schema
    let (additional_allowed, additional_schema) = match additional_props {
        Some(v) => match v.as_boolean_str() {
            Ok(s) => (s == "true", None),
            Err(_) => {
                if v.kind() == JsonValueKind::Object {
                    (true, Some(v))
                } else {
                    return Err(EvalError::Fatal(format!(
                        "at '{path}': additionalProperties must be a boolean or an object"
                    )));
                }
            }
        },
        None => (true, None),
    };

    if let Some(props) = properties {
        if props.kind() != JsonValueKind::Object {
            return Err(EvalError::Fatal(format!(
                "at '{path}': properties must be an object"
            )));
        }
        for (key_name, val) in &entries {
            if let Some(prop_schema) = member_opt(props, key_name) {
                let p = field_path(path, key_name);
                validate_value(*val, prop_schema, &p, depth + 1, eval)?;
            } else if !additional_allowed {
                return Err(EvalError::Mismatch(format!(
                    "at '{}': additional property not allowed",
                    field_path(path, key_name)
                )));
            } else if let Some(add_schema) = additional_schema {
                let p = field_path(path, key_name);
                validate_value(*val, add_schema, &p, depth + 1, eval)?;
            }
        }
    } else if !additional_allowed {
        if let Some((key_name, _)) = entries.first() {
            return Err(EvalError::Mismatch(format!(
                "at '{}': additional property not allowed",
                field_path(path, key_name)
            )));
        }
    } else if let Some(add_schema) = additional_schema {
        // No properties defined but additionalProperties is a schema → validate all keys
        for (key_name, val) in &entries {
            let p = field_path(path, key_name);
            validate_value(*val, add_schema, &p, depth + 1, eval)?;
        }
    }

    Ok(())
}

fn validate_array(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
    depth: u32,
    eval: &mut Eval<'_>,
) -> Result<(), EvalError> {
    let items_schema = member_opt(schema, "items");
    if let Some(items) = items_schema
        && items.kind() == JsonValueKind::Array
    {
        let p = if path.is_empty() { "schema" } else { path };
        return Err(EvalError::Fatal(format!(
            "at '{p}': array-form 'items' (tuple validation) is not supported"
        )));
    }

    let unique = match member_opt(schema, "uniqueItems") {
        Some(v) => match v.as_boolean_str() {
            Ok(s) => s == "true",
            Err(_) => {
                let p = if path.is_empty() { "schema" } else { path };
                return Err(EvalError::Fatal(format!(
                    "at '{p}': uniqueItems must be a boolean"
                )));
            }
        },
        None => false,
    };

    let mut count = 0usize;
    let mut seen: Option<HashSet<String>> = unique.then(HashSet::new);
    for (i, elem) in value.to_array().map_err(EvalError::fatal)?.enumerate() {
        spend_node(eval, path)?;
        count += 1;
        if let Some(items) = items_schema {
            let p = field_path(path, &format!("[{i}]"));
            validate_value(elem, items, &p, depth + 1, eval)?;
        }
        if let Some(seen) = seen.as_mut()
            && !seen.insert(canonical_key(elem, 0))
        {
            let p = field_path(path, &format!("[{i}]"));
            return Err(EvalError::Mismatch(format!(
                "at '{p}': array elements are not unique"
            )));
        }
    }

    let field = if path.is_empty() { "value" } else { path };
    if let Some(min_val) = member_opt(schema, "minItems") {
        let min_s = min_val.as_integer_str().map_err(EvalError::fatal)?;
        let min: usize = min_s
            .parse()
            .map_err(|_| EvalError::Fatal(format!("invalid minItems '{min_s}'")))?;
        if count < min {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': array has {count} items, is less than minItems {min}"
            )));
        }
    }
    if let Some(max_val) = member_opt(schema, "maxItems") {
        let max_s = max_val.as_integer_str().map_err(EvalError::fatal)?;
        let max: usize = max_s
            .parse()
            .map_err(|_| EvalError::Fatal(format!("invalid maxItems '{max_s}'")))?;
        if count > max {
            return Err(EvalError::Mismatch(format!(
                "at '{field}': array has {count} items, is greater than maxItems {max}"
            )));
        }
    }
    Ok(())
}

/// Canonical equality key for `uniqueItems` — JSON Schema value equality
/// is key-order- and number-representation-insensitive, so object members
/// sort and numbers normalize through `ExactDecimal` (the same semantics
/// [`json_values_equal`] uses: `-0.0` equals `0`). Length prefixes keep
/// the encoding injective; nodes deeper than the schema depth cap fall
/// back to their raw text (still deterministic).
fn canonical_key(v: RawJsonValue<'_, '_>, depth: u32) -> String {
    if depth > MAX_SCHEMA_DEPTH {
        return format!("r{}", v.as_raw_str());
    }
    match v.kind() {
        JsonValueKind::Null => "N".to_string(),
        JsonValueKind::Boolean => {
            if v.as_boolean_str().ok() == Some("true") {
                "Bt".to_string()
            } else {
                "Bf".to_string()
            }
        }
        JsonValueKind::Integer | JsonValueKind::Float => match v
            .as_number_str()
            .ok()
            .and_then(|s| ExactDecimal::parse(s).ok())
        {
            Some(d) => format!(
                "D{}{}:{:?}",
                if d.negative { "-" } else { "+" },
                d.exp,
                d.digits
            ),
            None => format!("r{}", v.as_raw_str()),
        },
        JsonValueKind::String => match v.to_unquoted_string_str() {
            Ok(s) => format!("S{}:{}", s.len(), s),
            Err(_) => format!("r{}", v.as_raw_str()),
        },
        JsonValueKind::Array => match v.to_array() {
            Ok(items) => {
                let mut out = String::from("A[");
                for (i, item) in items.enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&canonical_key(item, depth + 1));
                }
                out.push(']');
                out
            }
            Err(_) => format!("r{}", v.as_raw_str()),
        },
        JsonValueKind::Object => match v.to_object() {
            Ok(members) => {
                let mut pairs: Vec<(String, String)> = members
                    .filter_map(|(k, val)| {
                        str_val(k)
                            .ok()
                            .map(|name| (name.into_owned(), canonical_key(val, depth + 1)))
                    })
                    .collect();
                pairs.sort();
                let mut out = String::from("O{");
                for (i, (name, key)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!("{}:{}={}", name.len(), name, key));
                }
                out.push('}');
                out
            }
            Err(_) => format!("r{}", v.as_raw_str()),
        },
    }
}

// ---------------------------------------------------------------------------
// Type checking
// ---------------------------------------------------------------------------

fn type_matches(value: RawJsonValue<'_, '_>, expected: &str) -> Result<bool, EvalError> {
    let kind = value.kind();
    let ok = match expected {
        "string" => kind == JsonValueKind::String,
        "number" => kind.is_number(),
        "integer" => kind == JsonValueKind::Integer,
        "boolean" => kind == JsonValueKind::Boolean,
        "array" => kind == JsonValueKind::Array,
        "object" => kind == JsonValueKind::Object,
        "null" => kind == JsonValueKind::Null,
        _ => {
            return Err(EvalError::Fatal(format!(
                "unknown schema type '{expected}'"
            )));
        }
    };
    Ok(ok)
}

fn check_type(value: RawJsonValue<'_, '_>, expected: &str, path: &str) -> Result<(), EvalError> {
    if !type_matches(value, expected)? {
        let actual = kind_name(value.kind());
        let field = if path.is_empty() { "value" } else { path };
        return Err(EvalError::Mismatch(format!(
            "at '{field}': should be {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn kind_name(kind: JsonValueKind) -> &'static str {
    match kind {
        JsonValueKind::Null => "null",
        JsonValueKind::Boolean => "boolean",
        JsonValueKind::Integer => "integer",
        JsonValueKind::Float => "number",
        JsonValueKind::String => "string",
        JsonValueKind::Array => "array",
        JsonValueKind::Object => "object",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// RF05b comparison harness — the pre-RF05b evaluator kept verbatim
/// (per-request `RawJson::parse`, uncached `$ref`/`pattern`) so the
/// equivalence suite can check the prepared evaluator answers every
/// fixed input identically. Test-only; the product ships one evaluator.
#[cfg(test)]
mod legacy;

#[cfg(test)]
mod tests;
