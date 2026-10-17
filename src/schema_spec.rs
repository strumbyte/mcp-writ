//! Shared declaration of the JSON Schema subset `args_schema` enforces.
//!
//! Three consumers need the same answer to "can this schema be enforced":
//! the Auditor's evaluator (`auditor::schema_validator`), the policy
//! loader's scan (`policy::validator`), and `generate-policy` (unsupported
//! schemas are dropped with a REVIEW note instead of being copied). A
//! layer-0 leaf holds that answer once — `policy` may not reach up into
//! the `auditor` module that owns the evaluator.
//!
//! Dialect: JSON Schema 2020-12. `format` is annotation-only (the 2020-12
//! default) — accepted, never enforced. `$ref` resolves same-document
//! targets only (`#` or `#/<json-pointer>`); external references are
//! rejected. Data positions (`enum`, `const`, `default`, `examples`) are
//! never scanned or evaluated as schemas.

use std::borrow::Cow;
use std::collections::HashSet;

use nojson::{JsonValueKind, RawJson, RawJsonValue};

/// Schema-object keys the evaluator understands. Everything else is
/// rejected at call time and reported by [`unsupported_schema_findings`]
/// at load/generate time.
pub(crate) const SUPPORTED_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "anyOf",
    "oneOf",
    "allOf",
    "$ref",
    "format",
    "description",
    "title",
    "default",
    "examples",
    "$schema",
    "$id",
    "$comment",
    "definitions",
    "$defs",
];

/// Recursion limit shared by the evaluator and the static scan — bounds
/// nested `properties`/`items`/`$defs` structures and terminates `$ref`
/// cycles on recursive models. 64 levels covers any real-world
/// `inputSchema` by a wide margin while keeping worst-case recursion
/// comfortably inside a test-thread stack.
pub(crate) const MAX_SCHEMA_DEPTH: u32 = 64;

/// Instance type names a `type` keyword may hold.
const VALID_TYPES: &[&str] = &[
    "string", "number", "integer", "boolean", "array", "object", "null",
];

/// Look up an optional member in a JSON object.
pub(crate) fn member_opt<'t, 'r>(
    obj: RawJsonValue<'t, 'r>,
    name: &str,
) -> Option<RawJsonValue<'t, 'r>> {
    obj.to_member(name).ok().and_then(|m| m.optional())
}

/// Extract the unquoted string content from a JSON string value.
pub(crate) fn str_val<'t>(v: RawJsonValue<'t, '_>) -> Result<Cow<'t, str>, String> {
    v.to_unquoted_string_str().map_err(|e| e.to_string())
}

/// Build a dotted/bracketed field path for error messages.
pub(crate) fn field_path(base: &str, field: &str) -> String {
    if base.is_empty() {
        field.to_string()
    } else if field.starts_with('[') {
        format!("{base}{field}")
    } else {
        format!("{base}.{field}")
    }
}

/// Reject schema objects carrying keywords the evaluator does not
/// implement — the call-time guard mirroring the load-time scan.
pub(crate) fn check_unsupported_keywords(
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    if schema.kind() != JsonValueKind::Object {
        return Ok(());
    }
    for (k, _) in schema.to_object().map_err(|e| e.to_string())? {
        let key_str = str_val(k)?;
        if !SUPPORTED_KEYWORDS.contains(&key_str.as_ref()) {
            let p = if path.is_empty() { "schema" } else { path };
            return Err(format!("at '{p}': unsupported schema keyword '{key_str}'"));
        }
    }
    Ok(())
}

/// Resolve a same-document `$ref` target against the schema root.
///
/// `#` names the root; `#/<json-pointer>` walks object members and array
/// indices with `~0`/`~1` escapes and URI-fragment percent-decoding.
/// Anything else — bare names, `file:`/`https:` URIs, anchors — is an
/// unsupported external reference.
pub(crate) fn resolve_local_ref<'t, 'r>(
    root: RawJsonValue<'t, 'r>,
    target: &str,
) -> Result<RawJsonValue<'t, 'r>, String> {
    let pointer = target.strip_prefix('#').ok_or_else(|| {
        format!("unsupported $ref '{target}': only same-document references (#…) are resolved")
    })?;
    if pointer.is_empty() {
        return Ok(root);
    }
    let pointer = pointer
        .strip_prefix('/')
        .ok_or_else(|| format!("unresolvable $ref '{target}': fragment is not a JSON pointer"))?;
    let pointer = percent_decode(pointer);
    let mut node = root;
    for raw_segment in pointer.split('/') {
        let segment = raw_segment.replace("~1", "/").replace("~0", "~");
        node = match node.kind() {
            JsonValueKind::Object => member_opt(node, &segment)
                .ok_or_else(|| format!("unresolvable $ref '{target}': missing key '{segment}'"))?,
            JsonValueKind::Array => {
                let idx: usize = segment.parse().map_err(|_| {
                    format!("unresolvable $ref '{target}': '{segment}' is not an array index")
                })?;
                node.to_array()
                    .map_err(|e| e.to_string())?
                    .nth(idx)
                    .ok_or_else(|| {
                        format!("unresolvable $ref '{target}': array index {idx} out of range")
                    })?
            }
            _ => {
                return Err(format!(
                    "unresolvable $ref '{target}': '{segment}' walks into a non-container"
                ));
            }
        };
    }
    Ok(node)
}

/// `%XX` byte escapes decoded as UTF-8 — invalid sequences pass through
/// verbatim, so a malformed fragment fails "unresolvable" rather than
/// silently matching a different member.
fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Sign-and-zero test on a raw JSON number literal without float
/// conversion — `1e-5000` is still positive, and `-0`/`0e5` are not.
fn is_positive_number_str(s: &str) -> bool {
    let s = s.trim();
    if s.starts_with('-') {
        return false;
    }
    s.bytes().any(|b| b.is_ascii_digit() && b != b'0')
}

/// Report the schema constructs in `schema_str` the evaluator does not
/// implement — the load-time scan backing "known-bad at load, not at
/// call". Findings cover unsupported keywords, malformed keyword values
/// (they would fail closed at call time anyway), non-local or
/// unresolvable `$ref`s, and schemas over the depth limit. An empty
/// result means the schema can be evaluated as written.
///
/// Schema positions are the only nodes visited: `enum`/`const`/`default`/
/// `examples` payloads are data and are never treated as subschemas.
pub fn unsupported_schema_findings(schema_str: &str) -> Vec<String> {
    let schema_json = match RawJson::parse(schema_str) {
        Ok(j) => j,
        Err(e) => return vec![format!("invalid args_schema JSON: {e}")],
    };
    let mut findings = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    scan_schema(
        schema_json.value(),
        "#",
        schema_json.value(),
        0,
        &mut findings,
        &mut visited,
    );
    findings
}

/// Findings are capped so a hostile schema cannot flood the load error.
const MAX_FINDINGS: usize = 16;

fn push_finding(findings: &mut Vec<String>, msg: String) {
    if findings.len() < MAX_FINDINGS {
        findings.push(msg);
    }
}

/// `ptr` is the JSON Pointer that names this node ("#" for the root) —
/// it doubles as the finding location and the `visited` key that stops
/// `$ref` rescanning and self-referential cycles.
fn scan_schema(
    schema: RawJsonValue<'_, '_>,
    ptr: &str,
    root: RawJsonValue<'_, '_>,
    depth: u32,
    findings: &mut Vec<String>,
    visited: &mut HashSet<String>,
) {
    if findings.len() >= MAX_FINDINGS || !visited.insert(ptr.to_string()) {
        return;
    }
    if depth > MAX_SCHEMA_DEPTH {
        push_finding(
            findings,
            format!("{ptr}: schema exceeds depth limit {MAX_SCHEMA_DEPTH}"),
        );
        return;
    }
    match schema.kind() {
        JsonValueKind::Boolean => return,
        JsonValueKind::Object => {}
        _ => {
            push_finding(
                findings,
                format!("{ptr}: schema must be a boolean or an object"),
            );
            return;
        }
    }

    if let Ok(members) = schema.to_object() {
        for (k, v) in members {
            let Ok(key) = str_val(k) else {
                push_finding(findings, format!("{ptr}: non-string schema member key"));
                continue;
            };
            if !SUPPORTED_KEYWORDS.contains(&key.as_ref()) {
                push_finding(
                    findings,
                    format!("{ptr}: unsupported schema keyword '{key}'"),
                );
                continue;
            }
            check_keyword_shape(&key, v, ptr, root, findings, visited, depth);
        }
    }

    // Recurse into schema positions only.
    if let Some(props) = member_opt(schema, "properties")
        && props.kind() == JsonValueKind::Object
        && let Ok(members) = props.to_object()
    {
        for (k, sub) in members {
            let name = str_val(k).unwrap_or(Cow::Borrowed("?"));
            scan_schema(
                sub,
                &format!("{ptr}/properties/{name}"),
                root,
                depth + 1,
                findings,
                visited,
            );
        }
    }
    if let Some(items) = member_opt(schema, "items")
        && matches!(items.kind(), JsonValueKind::Object | JsonValueKind::Boolean)
    {
        scan_schema(
            items,
            &format!("{ptr}/items"),
            root,
            depth + 1,
            findings,
            visited,
        );
    }
    if let Some(ap) = member_opt(schema, "additionalProperties")
        && ap.kind() == JsonValueKind::Object
    {
        scan_schema(
            ap,
            &format!("{ptr}/additionalProperties"),
            root,
            depth + 1,
            findings,
            visited,
        );
    }
    for name in ["anyOf", "oneOf", "allOf"] {
        if let Some(list) = member_opt(schema, name)
            && list.kind() == JsonValueKind::Array
            && let Ok(branches) = list.to_array()
        {
            for (i, sub) in branches.enumerate() {
                scan_schema(
                    sub,
                    &format!("{ptr}/{name}/{i}"),
                    root,
                    depth + 1,
                    findings,
                    visited,
                );
            }
        }
    }
    for name in ["$defs", "definitions"] {
        if let Some(defs) = member_opt(schema, name)
            && defs.kind() == JsonValueKind::Object
            && let Ok(members) = defs.to_object()
        {
            for (k, sub) in members {
                let member = str_val(k).unwrap_or(Cow::Borrowed("?"));
                scan_schema(
                    sub,
                    &format!("{ptr}/{name}/{member}"),
                    root,
                    depth + 1,
                    findings,
                    visited,
                );
            }
        }
    }
}

/// Shape-check a known keyword's value. Malformed values fail closed at
/// call time; flagging them at load is the point of the scan.
fn check_keyword_shape(
    key: &str,
    v: RawJsonValue<'_, '_>,
    ptr: &str,
    root: RawJsonValue<'_, '_>,
    findings: &mut Vec<String>,
    visited: &mut HashSet<String>,
    depth: u32,
) {
    let kind = v.kind();
    match key {
        "type" => {
            let mut names = Vec::new();
            match kind {
                JsonValueKind::String => {
                    names.push(str_val(v).unwrap_or_default().into_owned());
                }
                JsonValueKind::Array => {
                    let mut elems = v.to_array().into_iter().flatten().peekable();
                    if elems.peek().is_none() {
                        push_finding(findings, format!("{ptr}: 'type' array must not be empty"));
                    }
                    for t in elems {
                        if t.kind() == JsonValueKind::String {
                            names.push(str_val(t).unwrap_or_default().into_owned());
                        } else {
                            push_finding(
                                findings,
                                format!("{ptr}: 'type' array elements must be strings"),
                            );
                        }
                    }
                }
                _ => {
                    push_finding(
                        findings,
                        format!("{ptr}: 'type' must be a string or an array of type names"),
                    );
                }
            }
            for name in names {
                if !VALID_TYPES.contains(&name.as_str()) {
                    push_finding(findings, format!("{ptr}: unknown schema type '{name}'"));
                }
            }
        }
        "enum" | "examples" => {
            if kind != JsonValueKind::Array {
                push_finding(findings, format!("{ptr}: '{key}' must be an array"));
            }
        }
        "required" => {
            let ok = kind == JsonValueKind::Array
                && v.to_array()
                    .into_iter()
                    .flatten()
                    .all(|t| t.kind() == JsonValueKind::String);
            if !ok {
                push_finding(
                    findings,
                    format!("{ptr}: 'required' must be an array of strings"),
                );
            }
        }
        "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
            if !kind.is_number() {
                push_finding(findings, format!("{ptr}: '{key}' must be a number"));
            }
        }
        "multipleOf" => {
            let ok = v.as_number_str().ok().is_some_and(is_positive_number_str);
            if !ok {
                push_finding(
                    findings,
                    format!("{ptr}: 'multipleOf' must be a number greater than 0"),
                );
            }
        }
        "minLength" | "maxLength" | "minItems" | "maxItems" => {
            let ok = v
                .as_integer_str()
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .is_some_and(|n| n >= 0);
            if !ok {
                push_finding(
                    findings,
                    format!("{ptr}: '{key}' must be a non-negative integer"),
                );
            }
        }
        "uniqueItems" => {
            if kind != JsonValueKind::Boolean {
                push_finding(findings, format!("{ptr}: 'uniqueItems' must be a boolean"));
            }
        }
        "pattern" => match str_val(v) {
            Ok(p) => {
                if let Err(e) = regex_lite::Regex::new(&p) {
                    push_finding(findings, format!("{ptr}: invalid regex pattern '{p}': {e}"));
                }
            }
            Err(_) => push_finding(findings, format!("{ptr}: 'pattern' must be a string")),
        },
        "format" | "title" | "description" | "$comment" | "$schema" | "$id" => {
            if kind != JsonValueKind::String {
                push_finding(findings, format!("{ptr}: '{key}' must be a string"));
            }
        }
        "properties" | "$defs" | "definitions" => {
            if kind != JsonValueKind::Object {
                push_finding(findings, format!("{ptr}: '{key}' must be an object"));
            }
        }
        "additionalProperties" => {
            if !matches!(kind, JsonValueKind::Boolean | JsonValueKind::Object) {
                push_finding(
                    findings,
                    format!("{ptr}: 'additionalProperties' must be a boolean or an object"),
                );
            }
        }
        "items" => {
            if kind == JsonValueKind::Array {
                push_finding(
                    findings,
                    format!("{ptr}: array-form 'items' (tuple validation) is not supported"),
                );
            } else if !matches!(kind, JsonValueKind::Object | JsonValueKind::Boolean) {
                push_finding(findings, format!("{ptr}: 'items' must be a schema"));
            }
        }
        "anyOf" | "oneOf" | "allOf" => {
            let ok =
                kind == JsonValueKind::Array && v.to_array().into_iter().flatten().next().is_some();
            if !ok {
                push_finding(
                    findings,
                    format!("{ptr}: '{key}' must be a non-empty array of schemas"),
                );
            }
        }
        "$ref" => match str_val(v) {
            Err(_) => push_finding(findings, format!("{ptr}: '$ref' must be a string")),
            Ok(target) => match resolve_local_ref(root, &target) {
                Err(e) => push_finding(findings, format!("{ptr}: {e}")),
                Ok(node) => {
                    // `target` is already the canonical "#…" pointer — it
                    // is the visited key, so a self-referential schema
                    // terminates here instead of recursing.
                    scan_schema(node, &target, root, depth + 1, findings, visited);
                }
            },
        },
        // `const`, `default`, `propertyNames`-absent annotations: any value is
        // data, nothing to check.
        _ => {}
    }
}

#[cfg(test)]
mod tests;
