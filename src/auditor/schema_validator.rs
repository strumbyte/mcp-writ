use std::borrow::Cow;

use nojson::{JsonValueKind, RawJson, RawJsonValue};

/// Resolve an args_schema reference to a JSON schema string.
///
/// - If the reference starts with `@`, the rest is treated as a file path.
/// - Otherwise, it is treated as inline JSON.
pub fn resolve_schema(schema_ref: &str) -> Result<String, String> {
    if let Some(path) = schema_ref.strip_prefix('@') {
        let path = path.trim();

        // Canonicalize the path to resolve symlinks and `..` components,
        // then verify the result lives under the current working directory.
        let canonical = std::fs::canonicalize(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("failed to read schema file '{path}': {e}")
            } else {
                format!("failed to resolve schema file path '{path}': {e}")
            }
        })?;
        let base_raw = std::env::current_dir()
            .map_err(|e| format!("failed to determine working directory: {e}"))?;
        let base = std::fs::canonicalize(&base_raw).unwrap_or(base_raw);
        if !canonical.starts_with(&base) {
            return Err(format!(
                "path traversal: schema file '{}' resolves outside the working directory",
                canonical.display(),
            ));
        }

        std::fs::read_to_string(&canonical)
            .map_err(|e| format!("failed to read schema file '{path}': {e}"))
    } else {
        Ok(schema_ref.to_string())
    }
}

/// Validate tool arguments against a JSON Schema string.
///
/// Returns `Ok(())` if the arguments satisfy the schema, or `Err` with a
/// human-readable description of the first violation found.
pub fn validate_arguments(arguments: RawJsonValue<'_, '_>, schema_str: &str) -> Result<(), String> {
    let schema_json =
        RawJson::parse(schema_str).map_err(|e| format!("invalid args_schema JSON: {e}"))?;
    validate_value(arguments, schema_json.value(), "")
}

// ---------------------------------------------------------------------------
// Core recursive validator
// ---------------------------------------------------------------------------

fn validate_value(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    // Boolean schema handling (JSON Schema 2020-12 §4.3.2)
    // "A boolean schema is a schema which is either the boolean value true or false.
    // The schema true always validates successfully; the schema false always fails to validate."
    match schema.kind() {
        JsonValueKind::Boolean => {
            if schema.as_boolean_str().map_err(|e| e.to_string())? == "true" {
                return Ok(());
            } else {
                let p = if path.is_empty() { "value" } else { path };
                return Err(format!("at '{p}': schema is false, value rejected"));
            }
        }
        JsonValueKind::Object => {}
        _ => {
            let p = if path.is_empty() { "schema" } else { path };
            return Err(format!("at '{p}': schema must be a boolean or an object"));
        }
    }

    // 0. Check for unsupported schema keywords
    check_unsupported_keywords(schema, path)?;

    // 1. Check "type" constraint
    if let Some(type_val) = member_opt(schema, "type") {
        let expected = str_val(type_val)?;
        check_type(value, &expected, path)?;
    }

    // 2. Check "enum" constraint
    if let Some(enum_val) = member_opt(schema, "enum") {
        check_enum(value, enum_val, path)?;
    }

    // 3. Numeric constraints (minimum, maximum, exclusiveMinimum, exclusiveMaximum)
    check_numeric_constraints(value, schema, path)?;

    // 4. String constraints (minLength, maxLength, pattern)
    check_string_constraints(value, schema, path)?;

    // 5. Object-specific: required, properties, additionalProperties
    if value.kind() == JsonValueKind::Object {
        validate_object(value, schema, path)?;
    }

    // 6. Array-specific: items
    if value.kind() == JsonValueKind::Array
        && let Some(items_schema) = member_opt(schema, "items")
    {
        for (i, elem) in value.to_array().map_err(|e| e.to_string())?.enumerate() {
            let p = field_path(path, &format!("[{i}]"));
            validate_value(elem, items_schema, &p)?;
        }
    }

    Ok(())
}

fn check_unsupported_keywords(schema: RawJsonValue<'_, '_>, path: &str) -> Result<(), String> {
    if schema.kind() != JsonValueKind::Object {
        return Ok(());
    }
    const ALLOWED_KEYWORDS: &[&str] = &[
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
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

    for (k, _) in schema.to_object().map_err(|e| e.to_string())? {
        let key_str = str_val(k)?;
        if !ALLOWED_KEYWORDS.contains(&key_str.as_ref()) {
            let p = if path.is_empty() { "schema" } else { path };
            return Err(format!(
                "at '{p}': unsupported schema keyword '{}'",
                key_str
            ));
        }
    }
    Ok(())
}

fn check_enum(
    value: RawJsonValue<'_, '_>,
    enum_val: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    let items = enum_val
        .to_array()
        .map_err(|e| format!("at '{path}': enum must be an array: {e}"))?;
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
        return Err(format!("at '{field}': value {val_raw} is not in enum"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactDecimal {
    negative: bool,
    digits: Vec<u8>,
    exp: i64,
}

impl ExactDecimal {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty numeric string".to_string());
        }

        let (negative, rest) = if let Some(stripped) = s.strip_prefix('-') {
            (true, stripped)
        } else if let Some(stripped) = s.strip_prefix('+') {
            (false, stripped)
        } else {
            (false, s)
        };

        let (mantissa, exp_val) = if let Some(idx) = rest.find(['e', 'E']) {
            let exp_str = &rest[idx + 1..];
            let exp_parsed: i64 = exp_str
                .parse()
                .map_err(|e| format!("invalid exponent '{exp_str}': {e}"))?;
            (&rest[..idx], exp_parsed)
        } else {
            (rest, 0i64)
        };

        let (int_part, frac_part) = if let Some(idx) = mantissa.find('.') {
            (&mantissa[..idx], &mantissa[idx + 1..])
        } else {
            (mantissa, "")
        };

        let mut raw_digits = Vec::new();
        for b in int_part.bytes() {
            if b.is_ascii_digit() {
                raw_digits.push(b - b'0');
            } else {
                return Err(format!("invalid character in integer part of '{s}'"));
            }
        }
        let int_len = raw_digits.len() as i64;

        for b in frac_part.bytes() {
            if b.is_ascii_digit() {
                raw_digits.push(b - b'0');
            } else {
                return Err(format!("invalid character in fraction part of '{s}'"));
            }
        }

        let first_non_zero = raw_digits.iter().position(|&d| d != 0);
        let Some(start_idx) = first_non_zero else {
            return Ok(ExactDecimal {
                negative: false,
                digits: Vec::new(),
                exp: 0,
            });
        };

        let last_non_zero = raw_digits.iter().rposition(|&d| d != 0).unwrap();
        let trimmed_digits = raw_digits[start_idx..=last_non_zero].to_vec();

        let exp = (int_len - 1 - (start_idx as i64))
            .checked_add(exp_val)
            .ok_or_else(|| "exponent overflow".to_string())?;

        Ok(ExactDecimal {
            negative,
            digits: trimmed_digits,
            exp,
        })
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        let self_zero = self.digits.is_empty();
        let other_zero = other.digits.is_empty();

        if self_zero && other_zero {
            return Ordering::Equal;
        }
        if self_zero {
            return if other.negative {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        if other_zero {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.cmp_abs(other),
            (true, true) => other.cmp_abs(self),
        }
    }

    fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        if self.exp != other.exp {
            return self.exp.cmp(&other.exp);
        }

        let min_len = self.digits.len().min(other.digits.len());
        for i in 0..min_len {
            match self.digits[i].cmp(&other.digits[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        self.digits.len().cmp(&other.digits.len())
    }
}

fn compare_numeric_strings(a: &str, b: &str) -> Result<std::cmp::Ordering, String> {
    let da = ExactDecimal::parse(a)?;
    let db = ExactDecimal::parse(b)?;
    Ok(da.cmp(&db))
}

fn numbers_equal(a: &str, b: &str) -> bool {
    if let (Ok(da), Ok(db)) = (ExactDecimal::parse(a), ExactDecimal::parse(b)) {
        da.cmp(&db) == std::cmp::Ordering::Equal
    } else {
        a == b
    }
}

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
        _ => a.as_raw_str().trim() == b.as_raw_str().trim(),
    }
}

fn check_numeric_constraints(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    if !value.kind().is_number() {
        return Ok(());
    }
    let num_str = value.as_number_str().map_err(|e| e.to_string())?;
    let field = if path.is_empty() { "value" } else { path };

    if let Some(min_val) = member_opt(schema, "minimum") {
        let min_s = min_val.as_number_str().map_err(|e| e.to_string())?;
        if compare_numeric_strings(num_str, min_s)? == std::cmp::Ordering::Less {
            return Err(format!(
                "at '{field}': {num_str} is less than minimum {min_s}"
            ));
        }
    }
    if let Some(max_val) = member_opt(schema, "maximum") {
        let max_s = max_val.as_number_str().map_err(|e| e.to_string())?;
        if compare_numeric_strings(num_str, max_s)? == std::cmp::Ordering::Greater {
            return Err(format!(
                "at '{field}': {num_str} is greater than maximum {max_s}"
            ));
        }
    }
    if let Some(ex_min_val) = member_opt(schema, "exclusiveMinimum") {
        let ex_min_s = ex_min_val.as_number_str().map_err(|e| e.to_string())?;
        let cmp = compare_numeric_strings(num_str, ex_min_s)?;
        if cmp == std::cmp::Ordering::Less || cmp == std::cmp::Ordering::Equal {
            return Err(format!(
                "at '{field}': {num_str} is less than or equal to exclusiveMinimum {ex_min_s}"
            ));
        }
    }
    if let Some(ex_max_val) = member_opt(schema, "exclusiveMaximum") {
        let ex_max_s = ex_max_val.as_number_str().map_err(|e| e.to_string())?;
        let cmp = compare_numeric_strings(num_str, ex_max_s)?;
        if cmp == std::cmp::Ordering::Greater || cmp == std::cmp::Ordering::Equal {
            return Err(format!(
                "at '{field}': {num_str} is greater than or equal to exclusiveMaximum {ex_max_s}"
            ));
        }
    }
    Ok(())
}

fn check_string_constraints(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    if value.kind() != JsonValueKind::String {
        return Ok(());
    }
    let s = str_val(value)?;
    let char_count = s.chars().count();
    let field = if path.is_empty() { "value" } else { path };

    if let Some(min_val) = member_opt(schema, "minLength") {
        let min_s = min_val.as_integer_str().map_err(|e| e.to_string())?;
        let min: usize = min_s
            .parse()
            .map_err(|_| format!("invalid minLength '{min_s}'"))?;
        if char_count < min {
            return Err(format!(
                "at '{field}': string length {char_count} is less than minLength {min}"
            ));
        }
    }
    if let Some(max_val) = member_opt(schema, "maxLength") {
        let max_s = max_val.as_integer_str().map_err(|e| e.to_string())?;
        let max: usize = max_s
            .parse()
            .map_err(|_| format!("invalid maxLength '{max_s}'"))?;
        if char_count > max {
            return Err(format!(
                "at '{field}': string length {char_count} is greater than maxLength {max}"
            ));
        }
    }
    if let Some(pat_val) = member_opt(schema, "pattern") {
        let pat_s = str_val(pat_val)?;
        let re = regex_lite::Regex::new(&pat_s)
            .map_err(|e| format!("at '{field}': invalid regex pattern '{}': {e}", pat_s))?;
        if !re.is_match(&s) {
            return Err(format!(
                "at '{field}': string does not match pattern '{}'",
                pat_s
            ));
        }
    }
    Ok(())
}

fn validate_object(
    value: RawJsonValue<'_, '_>,
    schema: RawJsonValue<'_, '_>,
    path: &str,
) -> Result<(), String> {
    // Collect all (key, value) entries in a single pass (avoids double iteration).
    let mut entries: Vec<(String, RawJsonValue<'_, '_>)> = Vec::new();
    for (key, val) in value.to_object().map_err(|e| e.to_string())? {
        entries.push((str_val(key)?.into_owned(), val));
    }

    // --- required -----------------------------------------------------------
    if let Some(required_val) = member_opt(schema, "required") {
        for req in required_val.to_array().map_err(|e| e.to_string())? {
            let name = str_val(req)?;
            if !entries.iter().any(|(k, _)| k == name.as_ref()) {
                return Err(format!(
                    "at '{}': missing required field",
                    field_path(path, &name)
                ));
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
                    return Err(format!(
                        "at '{path}': additionalProperties must be a boolean or an object"
                    ));
                }
            }
        },
        None => (true, None),
    };

    if let Some(props) = properties {
        if props.kind() != JsonValueKind::Object {
            return Err(format!("at '{path}': properties must be an object"));
        }
        for (key_name, val) in &entries {
            if let Some(prop_schema) = member_opt(props, key_name) {
                let p = field_path(path, key_name);
                validate_value(*val, prop_schema, &p)?;
            } else if !additional_allowed {
                return Err(format!(
                    "at '{}': additional property not allowed",
                    field_path(path, key_name)
                ));
            } else if let Some(add_schema) = additional_schema {
                let p = field_path(path, key_name);
                validate_value(*val, add_schema, &p)?;
            }
        }
    } else if !additional_allowed {
        if let Some((key_name, _)) = entries.first() {
            return Err(format!(
                "at '{}': additional property not allowed",
                field_path(path, key_name)
            ));
        }
    } else if let Some(add_schema) = additional_schema {
        // No properties defined but additionalProperties is a schema → validate all keys
        for (key_name, val) in &entries {
            let p = field_path(path, key_name);
            validate_value(*val, add_schema, &p)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Type checking
// ---------------------------------------------------------------------------

fn check_type(value: RawJsonValue<'_, '_>, expected: &str, path: &str) -> Result<(), String> {
    let kind = value.kind();
    let ok = match expected {
        "string" => kind == JsonValueKind::String,
        "number" => kind.is_number(),
        "integer" => kind == JsonValueKind::Integer,
        "boolean" => kind == JsonValueKind::Boolean,
        "array" => kind == JsonValueKind::Array,
        "object" => kind == JsonValueKind::Object,
        "null" => kind == JsonValueKind::Null,
        _ => return Err(format!("unknown schema type '{expected}'")),
    };

    if !ok {
        let actual = kind_name(kind);
        let field = if path.is_empty() { "value" } else { path };
        return Err(format!("at '{field}': should be {expected}, got {actual}"));
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
// Helpers
// ---------------------------------------------------------------------------

/// Look up an optional member in a JSON object.
fn member_opt<'t, 'r>(obj: RawJsonValue<'t, 'r>, name: &str) -> Option<RawJsonValue<'t, 'r>> {
    obj.to_member(name).ok().and_then(|m| m.optional())
}

/// Extract the unquoted string content from a JSON string value.
fn str_val<'t>(v: RawJsonValue<'t, '_>) -> Result<Cow<'t, str>, String> {
    v.to_unquoted_string_str().map_err(|e| e.to_string())
}

/// Build a dotted/bracketed field path for error messages.
fn field_path(base: &str, field: &str) -> String {
    if base.is_empty() {
        field.to_string()
    } else if field.starts_with('[') {
        format!("{base}{field}")
    } else {
        format!("{base}.{field}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse arguments JSON and validate against schema JSON.
    fn check(args: &str, schema: &str) -> Result<(), String> {
        let json = nojson::RawJson::parse(args).expect("invalid test args JSON");
        validate_arguments(json.value(), schema)
    }

    // --- type checks --------------------------------------------------------

    #[test]
    fn valid_string_property() {
        let schema =
            r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#;
        assert!(check(r#"{"path":"/tmp/file.txt"}"#, schema).is_ok());
    }

    #[test]
    fn wrong_type_string_got_integer() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}}}"#;
        let err = check(r#"{"path":123}"#, schema).unwrap_err();
        assert!(err.contains("should be string"), "got: {err}");
        assert!(err.contains("path"), "got: {err}");
    }

    #[test]
    fn number_accepts_integer_and_float() {
        let schema = r#"{"type":"object","properties":{"count":{"type":"number"}}}"#;
        assert!(check(r#"{"count":42}"#, schema).is_ok());
        assert!(check(r#"{"count":3.14}"#, schema).is_ok());
    }

    #[test]
    fn integer_rejects_float() {
        let schema = r#"{"type":"object","properties":{"count":{"type":"integer"}}}"#;
        assert!(check(r#"{"count":42}"#, schema).is_ok());
        let err = check(r#"{"count":3.14}"#, schema).unwrap_err();
        assert!(err.contains("should be integer"), "got: {err}");
    }

    #[test]
    fn boolean_type() {
        let schema = r#"{"type":"object","properties":{"flag":{"type":"boolean"}}}"#;
        assert!(check(r#"{"flag":true}"#, schema).is_ok());
        assert!(check(r#"{"flag":false}"#, schema).is_ok());
        let err = check(r#"{"flag":"yes"}"#, schema).unwrap_err();
        assert!(err.contains("should be boolean"), "got: {err}");
    }

    #[test]
    fn null_type() {
        let schema = r#"{"type":"object","properties":{"v":{"type":"null"}}}"#;
        assert!(check(r#"{"v":null}"#, schema).is_ok());
        let err = check(r#"{"v":0}"#, schema).unwrap_err();
        assert!(err.contains("should be null"), "got: {err}");
    }

    #[test]
    fn root_type_mismatch() {
        let schema = r#"{"type":"object"}"#;
        let err = check(r#""hello""#, schema).unwrap_err();
        assert!(err.contains("should be object"), "got: {err}");
    }

    // --- required -----------------------------------------------------------

    #[test]
    fn missing_required_field() {
        let schema =
            r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#;
        let err = check(r#"{}"#, schema).unwrap_err();
        assert!(err.contains("missing required field"), "got: {err}");
        assert!(err.contains("path"), "got: {err}");
    }

    #[test]
    fn multiple_required_first_missing() {
        let schema = r#"{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}"#;
        let err = check(r#"{"b":"ok"}"#, schema).unwrap_err();
        assert!(err.contains("'a'"), "got: {err}");
    }

    // --- additionalProperties -----------------------------------------------

    #[test]
    fn additional_properties_rejected() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false}"#;
        let err = check(r#"{"path":"/tmp","extra":"val"}"#, schema).unwrap_err();
        assert!(err.contains("additional property"), "got: {err}");
        assert!(err.contains("extra"), "got: {err}");
    }

    #[test]
    fn additional_properties_allowed_by_default() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}}}"#;
        assert!(check(r#"{"path":"/tmp","extra":"val"}"#, schema).is_ok());
    }

    #[test]
    fn additional_properties_no_properties_defined_rejects_all_keys() {
        let schema = r#"{"type":"object","additionalProperties":false}"#;
        let err = check(r#"{"anykey":"val"}"#, schema).unwrap_err();
        assert!(err.contains("additional property"), "got: {err}");
        assert!(err.contains("anykey"), "got: {err}");
    }

    #[test]
    fn additional_properties_no_properties_defined_empty_object_ok() {
        let schema = r#"{"type":"object","additionalProperties":false}"#;
        assert!(check(r#"{}"#, schema).is_ok());
    }

    #[test]
    fn required_with_additional_properties_false_no_properties_rejects_required_keys() {
        // JSON Schema: additionalProperties:false with no properties object
        // treats every instance key as additional.
        let schema = r#"{"type":"object","required":["name"],"additionalProperties":false}"#;
        let err = check(r#"{"name":"test"}"#, schema).unwrap_err();
        assert!(err.contains("additional property"), "got: {err}");
    }

    #[test]
    fn required_with_additional_properties_false_no_properties_rejects_extra() {
        let schema = r#"{"type":"object","required":["name"],"additionalProperties":false}"#;
        let err = check(r#"{"name":"test","extra":"bad"}"#, schema).unwrap_err();
        assert!(err.contains("additional property"), "got: {err}");
    }

    #[test]
    fn additional_properties_explicitly_allowed() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":true}"#;
        assert!(check(r#"{"path":"/tmp","extra":"val"}"#, schema).is_ok());
    }

    // --- additionalProperties as schema -------------------------------------

    #[test]
    fn additional_properties_schema_validates_extra_keys() {
        let schema = r#"{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":{"type":"integer"}}"#;
        assert!(check(r#"{"name":"test","count":42}"#, schema).is_ok());
        let err = check(r#"{"name":"test","count":"not_int"}"#, schema).unwrap_err();
        assert!(err.contains("should be integer"), "got: {err}");
        assert!(err.contains("count"), "got: {err}");
    }

    #[test]
    fn additional_properties_schema_no_properties_defined() {
        let schema = r#"{"type":"object","additionalProperties":{"type":"string"}}"#;
        assert!(check(r#"{"a":"ok","b":"fine"}"#, schema).is_ok());
        let err = check(r#"{"a":"ok","b":123}"#, schema).unwrap_err();
        assert!(err.contains("should be string"), "got: {err}");
        assert!(err.contains("b"), "got: {err}");
    }

    #[test]
    fn additional_properties_schema_known_props_still_validated() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":{"type":"integer"}}"#;
        // known property wrong type → error from properties schema
        let err = check(r#"{"path":123}"#, schema).unwrap_err();
        assert!(err.contains("should be string"), "got: {err}");
    }

    #[test]
    fn additional_properties_invalid_type_rejected() {
        // additionalProperties as a string (not boolean or object) should be rejected
        let schema = r#"{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":"invalid"}"#;
        let err = check(r#"{"name":"test"}"#, schema).unwrap_err();
        assert!(
            err.contains("additionalProperties must be a boolean or an object"),
            "got: {err}"
        );
    }

    #[test]
    fn additional_properties_array_type_rejected() {
        // additionalProperties as an array should also be rejected
        let schema = r#"{"type":"object","additionalProperties":[1,2,3]}"#;
        let err = check(r#"{"x":"val"}"#, schema).unwrap_err();
        assert!(
            err.contains("additionalProperties must be a boolean or an object"),
            "got: {err}"
        );
    }

    // --- array items --------------------------------------------------------

    #[test]
    fn array_items_validated() {
        let schema =
            r#"{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}}}"#;
        assert!(check(r#"{"tags":["a","b","c"]}"#, schema).is_ok());
        let err = check(r#"{"tags":["a",123]}"#, schema).unwrap_err();
        assert!(err.contains("should be string"), "got: {err}");
        assert!(err.contains("[1]"), "got: {err}");
    }

    // --- nested objects -----------------------------------------------------

    #[test]
    fn nested_object_validation() {
        let schema = r#"{"type":"object","properties":{"config":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}"#;
        assert!(check(r#"{"config":{"name":"test"}}"#, schema).is_ok());
        let err = check(r#"{"config":{}}"#, schema).unwrap_err();
        assert!(err.contains("missing required field"), "got: {err}");
        assert!(err.contains("config.name"), "got: {err}");
    }

    // --- schema resolution --------------------------------------------------

    #[test]
    fn resolve_inline_schema() {
        let r = resolve_schema(r#"{"type":"object"}"#).unwrap();
        assert_eq!(r, r#"{"type":"object"}"#);
    }

    #[test]
    fn resolve_file_path_traversal_rejected() {
        // The path must exist for canonicalize; /etc/passwd exists on macOS/Linux.
        // Even if it canonicalizes, it should be outside cwd and therefore rejected.
        let err = resolve_schema("@../../../etc/passwd").unwrap_err();
        // Either "failed to read" (if path doesn't exist) or "path traversal"
        assert!(
            err.contains("path traversal") || err.contains("failed to read schema file"),
            "got: {err}"
        );
    }

    #[test]
    fn resolve_file_nonexistent_rejected() {
        let err = resolve_schema("@/nonexistent/path/schema.json").unwrap_err();
        assert!(err.contains("failed to read schema file"), "got: {err}");
    }

    #[test]
    fn resolve_file_outside_cwd_rejected() {
        // Create a real file in temp_dir which is outside cwd
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("mcp_writ_outside_test_schema.json");
        std::fs::write(&test_file, r#"{"type":"object"}"#).unwrap();

        let err = resolve_schema(&format!("@{}", test_file.display())).unwrap_err();
        std::fs::remove_file(&test_file).ok();

        assert!(err.contains("path traversal"), "got: {err}");
    }

    #[test]
    fn resolve_file_reference() {
        // Write a schema file inside the project directory (under cwd), then resolve it.
        let cwd = std::env::current_dir().unwrap();
        let dir = cwd.join("target").join("mcp_writ_test_schema");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.json");
        std::fs::write(&path, r#"{"type":"object"}"#).unwrap();

        let r = resolve_schema(&format!("@{}", path.display())).unwrap();
        assert_eq!(r, r#"{"type":"object"}"#);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    // --- edge cases ---------------------------------------------------------

    #[test]
    fn invalid_schema_json() {
        let json = nojson::RawJson::parse(r#"{}"#).unwrap();
        let err = validate_arguments(json.value(), "not json");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("invalid args_schema JSON"));
    }

    #[test]
    fn schema_without_type_still_checks_properties() {
        let schema = r#"{"properties":{"x":{"type":"integer"}}}"#;
        assert!(check(r#"{"x":1}"#, schema).is_ok());
        let err = check(r#"{"x":"nope"}"#, schema).unwrap_err();
        assert!(err.contains("should be integer"), "got: {err}");
    }

    #[test]
    fn empty_schema_accepts_anything() {
        let schema = r#"{}"#;
        assert!(check(r#"{"any":"thing"}"#, schema).is_ok());
        assert!(check(r#"123"#, schema).is_ok());
    }

    #[test]
    fn empty_arguments_with_no_required() {
        let schema = r#"{"type":"object","properties":{"opt":{"type":"string"}}}"#;
        assert!(check(r#"{}"#, schema).is_ok());
    }

    // --- enum, min/max, unsupported keywords ---------------------------

    #[test]
    fn test_f15_enum_and_maximum_validation() {
        let schema = r#"{
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["read"]},
                "count": {"type": "integer", "maximum": 10}
            }
        }"#;

        // {"action":"delete","count":999} must be rejected
        let bad = r#"{"action":"delete","count":999}"#;
        let err = check(bad, schema);
        assert!(
            err.is_err(),
            "should reject invalid enum and count exceeding maximum"
        );

        // Valid case must succeed
        let good = r#"{"action":"read","count":5}"#;
        assert!(check(good, schema).is_ok());

        // Count exceeding maximum alone must fail
        let bad_count = r#"{"action":"read","count":15}"#;
        let err_count = check(bad_count, schema);
        assert!(err_count.is_err());
        assert!(
            err_count
                .unwrap_err()
                .contains("is greater than maximum 10")
        );
    }

    #[test]
    fn test_f15_unsupported_keywords_rejected() {
        let schema = r#"{
            "type": "object",
            "properties": {
                "val": {"type": "integer", "multipleOf": 2}
            }
        }"#;
        let err = check(r#"{"val":4}"#, schema);
        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .contains("unsupported schema keyword 'multipleOf'")
        );
    }

    // --- Boolean schema and numeric precision ---------------------------

    #[test]
    fn test_r13_boolean_schema_top_level() {
        // "false" schema rejects all inputs
        let false_schema = "false";
        let err = check(r#"{"name":"test"}"#, false_schema);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("schema is false, value rejected"));

        // "true" schema accepts any input
        let true_schema = "true";
        assert!(check(r#"{"name":"test"}"#, true_schema).is_ok());
        assert!(check(r#"123"#, true_schema).is_ok());
        assert!(check(r#""hello""#, true_schema).is_ok());
    }

    #[test]
    fn test_r13_boolean_schema_in_properties() {
        // {"properties":{"secret":false}} should reject any object with "secret"
        let schema = r#"{"type":"object","properties":{"secret":false}}"#;
        let err = check(r#"{"secret":"val"}"#, schema);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("schema is false, value rejected"));

        // When "secret" is not present, it is valid
        assert!(check(r#"{"other":"val"}"#, schema).is_ok());
    }

    #[test]
    fn test_r13_float_enum_precision() {
        // enum: [0.0] must NOT match 1e-17
        let schema = r#"{"type":"object","properties":{"val":{"enum":[0.0]}}}"#;
        assert!(check(r#"{"val":0.0}"#, schema).is_ok());
        assert!(check(r#"{"val":0}"#, schema).is_ok());

        let err = check(r#"{"val":1e-17}"#, schema);
        assert!(err.is_err(), "1e-17 must not match 0.0 in enum");
        assert!(err.unwrap_err().contains("is not in enum"));
    }

    #[test]
    fn test_r13_large_integer_maximum_precision() {
        // maximum: 9007199254740992 (2^53) must reject 9007199254740993 (2^53 + 1)
        let schema = r#"{"type":"object","properties":{"id":{"type":"integer","maximum":9007199254740992}}}"#;
        assert!(check(r#"{"id":9007199254740992}"#, schema).is_ok());

        let err = check(r#"{"id":9007199254740993}"#, schema);
        assert!(
            err.is_err(),
            "9007199254740993 must be rejected by maximum 9007199254740992"
        );
        assert!(
            err.unwrap_err()
                .contains("is greater than maximum 9007199254740992")
        );
    }

    #[test]
    fn test_s11_decimal_and_exponent_precision() {
        // Float and scientific notation must not bypass maximum boundary
        let schema_max = r#"{"type":"object","properties":{"val":{"maximum":9007199254740992}}}"#;
        assert!(check(r#"{"val":9007199254740992}"#, schema_max).is_ok());
        assert!(check(r#"{"val":9007199254740992.0}"#, schema_max).is_ok());

        let err_float = check(r#"{"val":9007199254740993.0}"#, schema_max);
        assert!(err_float.is_err(), "9007199254740993.0 must be rejected");

        let err_exp = check(r#"{"val":9.007199254740993e15}"#, schema_max);
        assert!(err_exp.is_err(), "9.007199254740993e15 must be rejected");

        // enum: [0] must not match 1e-400 (underflow in f64)
        let schema_enum = r#"{"type":"object","properties":{"val":{"enum":[0]}}}"#;
        assert!(check(r#"{"val":0}"#, schema_enum).is_ok());
        assert!(check(r#"{"val":0.0}"#, schema_enum).is_ok());
        assert!(check(r#"{"val":-0.0}"#, schema_enum).is_ok());

        let err_underflow = check(r#"{"val":1e-400}"#, schema_enum);
        assert!(err_underflow.is_err(), "1e-400 must not match enum [0]");
        assert!(err_underflow.unwrap_err().contains("is not in enum"));
    }
}
