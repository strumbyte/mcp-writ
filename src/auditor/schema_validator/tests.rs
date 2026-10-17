use super::*;

/// Helper: parse arguments JSON and validate against schema JSON.
fn check(args: &str, schema: &str) -> Result<(), String> {
    let json = nojson::RawJson::parse(args).expect("invalid test args JSON");
    validate_arguments(json.value(), schema)
}

// --- type checks --------------------------------------------------------

#[test]
fn valid_string_property() {
    let schema = r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#;
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
    let schema = r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}"#;
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
    let schema =
        r#"{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":false}"#;
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
    let schema =
        r#"{"type":"object","properties":{"path":{"type":"string"}},"additionalProperties":true}"#;
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
    // Anything outside the supported subset is rejected — fail-closed.
    // (`multipleOf` joined the supported set under PR-21; the guard must
    // still fire on keywords the evaluator does not implement.)
    let schema = r#"{
        "type": "object",
        "properties": {
            "val": {"type": "integer", "multipleOf": 2},
            "opt": {"patternProperties": {"^v": {"type": "integer"}}}
        }
    }"#;
    let err = check(r#"{"val":4,"opt":{"v1":2}}"#, schema);
    assert!(err.is_err());
    assert!(
        err.unwrap_err()
            .contains("unsupported schema keyword 'patternProperties'")
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
    let schema =
        r#"{"type":"object","properties":{"id":{"type":"integer","maximum":9007199254740992}}}"#;
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

// --- PR-21: expanded supported set --------------------------------------

#[test]
fn test_type_array_of_names() {
    // pydantic emits `type: ["integer", "null"]` for Optional fields.
    let schema =
        r#"{"type":"object","properties":{"ctx":{"type":["integer","null"],"minimum":0}}}"#;
    assert!(check(r#"{"ctx":5}"#, schema).is_ok());
    assert!(check(r#"{"ctx":null}"#, schema).is_ok());
    let err = check(r#"{"ctx":"x"}"#, schema).unwrap_err();
    assert!(err.contains("one of"), "got: {err}");
    // Bounds still apply to whichever alternative matched.
    assert!(check(r#"{"ctx":-1}"#, schema).is_err());
}

#[test]
fn test_type_array_shape_errors() {
    assert!(check(r#"1"#, r#"{"type":[]}"#).is_err());
    assert!(check(r#"1"#, r#"{"type":["string",5]}"#).is_err());
    assert!(check(r#"1"#, r#"{"type":5}"#).is_err());
}

#[test]
fn test_type_array_unknown_name_rejected() {
    // An unknown alternative is a malformed schema — it must fail even
    // when an earlier member already matched the instance.
    let err = check(r#""x""#, r#"{"type":["string","bogus"]}"#).unwrap_err();
    assert!(err.contains("unknown schema type 'bogus'"), "got: {err}");
    let err = check(r#"1"#, r#"{"type":"bogus"}"#).unwrap_err();
    assert!(err.contains("unknown schema type 'bogus'"), "got: {err}");
}

#[test]
fn test_any_of() {
    let schema = r#"{"type":"object","properties":{"ref":{"anyOf":[{"type":"string"},{"type":"array","items":{"type":"string"}}]}}}"#;
    assert!(check(r#"{"ref":"main"}"#, schema).is_ok());
    assert!(check(r#"{"ref":["a","b"]}"#, schema).is_ok());
    assert!(check(r#"{"ref":[1]}"#, schema).is_err());
    let err = check(r#"{"ref":42}"#, schema).unwrap_err();
    assert!(err.contains("anyOf"), "got: {err}");
}

#[test]
fn test_one_of() {
    let schema =
        r#"{"type":"object","properties":{"n":{"oneOf":[{"type":"string"},{"type":"integer"}]}}}"#;
    assert!(check(r#"{"n":3}"#, schema).is_ok());
    assert!(check(r#"{"n":"x"}"#, schema).is_ok());
    let err = check(r#"{"n":true}"#, schema).unwrap_err();
    assert!(err.contains("oneOf"), "got: {err}");
    // Matches both branches → rejected (exactly one required).
    let schema = r#"{"oneOf":[{"type":"number"},{"minimum":0}]}"#;
    assert!(check(r#"5"#, schema).is_err());
}

#[test]
fn test_all_of() {
    let schema = r#"{"type":"object","properties":{"s":{"allOf":[{"type":"string"},{"minLength":3},{"maxLength":5}]}}}"#;
    assert!(check(r#"{"s":"abcd"}"#, schema).is_ok());
    assert!(check(r#"{"s":"ab"}"#, schema).is_err());
    assert!(check(r#"{"s":"abcdef"}"#, schema).is_err());
}

#[test]
fn test_combinator_shape_errors() {
    assert!(check(r#"1"#, r#"{"anyOf":[]}"#).is_err());
    assert!(check(r#"1"#, r#"{"anyOf":{}}"#).is_err());
    assert!(check(r#"1"#, r#"{"oneOf":5}"#).is_err());
}

#[test]
fn test_combinator_fatal_branch_propagates() {
    // A malformed branch is a schema error, not a non-match — it rejects
    // the call even when a sibling branch would have matched.
    let err = check(r#""x""#, r#"{"anyOf":[{"not":{}},{"type":"string"}]}"#).unwrap_err();
    assert!(
        err.contains("unsupported schema keyword 'not'"),
        "got: {err}"
    );
    let err = check(r#""x""#, r#"{"oneOf":[{"anyOf":[]},{"type":"string"}]}"#).unwrap_err();
    assert!(err.contains("non-empty"), "got: {err}");
    // A fatal hiding *behind* the matching branch surfaces too — the
    // verdict is decided but the schema error must not pass silently.
    let err = check(r#""x""#, r#"{"anyOf":[{"type":"string"},{"not":{}}]}"#).unwrap_err();
    assert!(
        err.contains("unsupported schema keyword 'not'"),
        "got: {err}"
    );
    let err = check(r#""x""#, r#"{"oneOf":[{"type":"string"},{"anyOf":[]}]}"#).unwrap_err();
    assert!(err.contains("non-empty"), "got: {err}");
    // ... while a clean mismatch is still just a non-match.
    assert!(
        check(
            r#""x""#,
            r#"{"anyOf":[{"type":"integer"},{"type":"string"}]}"#
        )
        .is_ok()
    );
    assert!(
        check(
            r#""x""#,
            r#"{"oneOf":[{"type":"integer"},{"type":"string"}]}"#
        )
        .is_ok()
    );
}

#[test]
fn test_const() {
    let schema = r#"{"type":"object","properties":{"mode":{"const":"read"}}}"#;
    assert!(check(r#"{"mode":"read"}"#, schema).is_ok());
    assert!(check(r#"{"mode":"write"}"#, schema).is_err());
    // Numeric const: representation-insensitive.
    assert!(check(r#"-0.0"#, r#"{"const":0}"#).is_ok());
    // Object const: key order insignificant.
    assert!(check(r#"{"b":2,"a":1}"#, r#"{"const":{"a":1,"b":2}}"#).is_ok());
    assert!(check(r#"{"a":1,"b":3}"#, r#"{"const":{"a":1,"b":2}}"#).is_err());
}

#[test]
fn test_min_max_items() {
    let schema = r#"{"type":"object","properties":{"paths":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":3}}}"#;
    assert!(check(r#"{"paths":["a"]}"#, schema).is_ok());
    let err = check(r#"{"paths":[]}"#, schema).unwrap_err();
    assert!(err.contains("minItems"), "got: {err}");
    let err = check(r#"{"paths":["a","b","c","d"]}"#, schema).unwrap_err();
    assert!(err.contains("maxItems"), "got: {err}");
}

#[test]
fn test_unique_items() {
    let schema = r#"{"type":"object","properties":{"xs":{"type":"array","uniqueItems":true}}}"#;
    assert!(check(r#"{"xs":[1,2,3]}"#, schema).is_ok());
    let err = check(r#"{"xs":[1,2,1]}"#, schema).unwrap_err();
    assert!(err.contains("unique"), "got: {err}");
    // Number representation does not evade uniqueness (0 == -0.0 == 0e1).
    assert!(check(r#"{"xs":[0,-0.0]}"#, schema).is_err());
    // Object key order does not evade uniqueness either.
    assert!(check(r#"{"xs":[{"a":1,"b":2},{"b":2,"a":1}]}"#, schema).is_err());
    assert!(check(r#"{"xs":[{"a":1,"b":2},{"b":2,"a":3}]}"#, schema).is_ok());
}

#[test]
fn test_multiple_of() {
    // 0.3 % 0.1 == 0 exactly — no float fuzz.
    let schema = r#"{"type":"object","properties":{"q":{"type":"number","multipleOf":0.1}}}"#;
    assert!(check(r#"{"q":0.3}"#, schema).is_ok());
    assert!(check(r#"{"q":0.35}"#, schema).is_err());
    assert!(check(r#"9"#, r#"{"multipleOf":3}"#).is_ok());
    assert!(check(r#"10"#, r#"{"multipleOf":3}"#).is_err());
    // Scientific notation and zero.
    assert!(check(r#"0.007"#, r#"{"multipleOf":1e-3}"#).is_ok());
    assert!(check(r#"0"#, r#"{"multipleOf":2}"#).is_ok());
    // Fractional divisors work too.
    assert!(check(r#"1.5"#, r#"{"multipleOf":0.25}"#).is_ok());
    assert!(check(r#"1.6"#, r#"{"multipleOf":0.25}"#).is_err());
    // Non-positive or malformed divisors are schema errors, not passes.
    assert!(check(r#"4"#, r#"{"multipleOf":0}"#).is_err());
    assert!(check(r#"4"#, r#"{"multipleOf":-2}"#).is_err());
    assert!(check(r#"4"#, r#"{"multipleOf":"x"}"#).is_err());
    // Extreme scales are bounded, not materialized.
    assert!(check(r#"4"#, r#"{"multipleOf":1e1000000}"#).is_err());
}

#[test]
fn test_format_is_annotation_only() {
    // JSON Schema 2020-12: format is annotation-only by default —
    // accepted but never enforced.
    let schema = r#"{"type":"object","properties":{"url":{"type":"string","format":"uri"}}}"#;
    assert!(check(r#"{"url":"not a uri"}"#, schema).is_ok());
}

#[test]
fn test_ref_local() {
    let schema = r##"{"$defs":{"path":{"type":"string","minLength":1}},"type":"object","properties":{"src":{"$ref":"#/$defs/path"},"dst":{"$ref":"#/$defs/path"}},"required":["src"]}"##;
    assert!(check(r#"{"src":"/a","dst":"/b"}"#, schema).is_ok());
    assert!(check(r#"{"src":"","dst":"/b"}"#, schema).is_err());
    // Root self-reference.
    let schema = r##"{"type":"object","properties":{"x":{"$ref":"#"},"required":[]}}"##;
    assert!(check(r#"{"x":{"x":{}}}"#, schema).is_ok());
}

#[test]
fn test_ref_external_rejected() {
    let schema = r#"{"$ref":"https://example.com/schema.json"}"#;
    let err = check(r#"{}"#, schema).unwrap_err();
    assert!(err.contains("$ref"), "got: {err}");
    assert!(check(r#"{}"#, r#"{"$ref":42}"#).is_err());
}

#[test]
fn test_ref_cycle_bounded() {
    // A self-referential schema terminates via the depth limit rather
    // than recursing forever.
    let err = check(r#"{"a":1}"#, r##"{"$ref":"#"}"##).unwrap_err();
    assert!(err.contains("depth limit"), "got: {err}");
}

#[test]
fn test_combinator_budget_bounded() {
    // Each $defs layer `$ref`s the one below twice, so evaluation paths
    // genuinely double per layer (2^21 leaf evaluations) while the
    // schema text stays small — the branch budget must cut it off.
    let mut defs = String::from(r##""d0":{"type":"string"}"##);
    for i in 1..=21usize {
        defs.push_str(&format!(
            r##", "d{i}":{{"anyOf":[{{"$ref":"#/$defs/d{}"}},{{"$ref":"#/$defs/d{}"}}]}}"##,
            i - 1,
            i - 1
        ));
    }
    let schema = format!(r##"{{"$defs":{{{defs}}}, "$ref":"#/$defs/d21"}}"##);
    let err = check(r#"42"#, &schema).unwrap_err();
    assert!(err.contains("combinator evaluation limit"), "got: {err}");
}

#[test]
fn test_tuple_items_rejected() {
    let schema = r#"{"type":"array","items":[{"type":"string"},{"type":"integer"}]}"#;
    let err = check(r#"["a",1]"#, schema).unwrap_err();
    assert!(err.contains("array-form 'items'"), "got: {err}");
}

#[test]
fn test_deep_nesting_depth_limit() {
    // A `$defs` chain keeps the JSON shallow (under the parser's own
    // 128-node nesting cap) while driving evaluation past
    // MAX_SCHEMA_DEPTH — the realistic deep-recursion shape.
    let mut defs = String::new();
    for i in 0..(MAX_SCHEMA_DEPTH as usize + 8) {
        defs.push_str(&format!(r##""d{i}":{{"$ref":"#/$defs/d{}"}},"##, i + 1));
    }
    defs.push_str(&format!(r#""d{}":true"#, MAX_SCHEMA_DEPTH + 8));
    let schema = format!(r##"{{"$defs":{{{defs}}},"$ref":"#/$defs/d0"}}"##);
    let err = check(r#"1"#, &schema).unwrap_err();
    assert!(err.contains("depth limit"), "got: {err}");
}

// --- Real MCP server input schemas --------------------------------------

/// mcp-server-git (pydantic): Optional fields surface as `anyOf` +
/// `type` arrays — the shape F-06 flagged as unsupported.
#[test]
fn test_real_git_server_schema() {
    // abridged GitLog / GitDiff inputSchema, verbatim keyword shapes
    let schema = r#"{
        "type":"object",
        "properties":{
            "repo_path":{"type":"string","title":"Repo Path","description":"Path to git repository"},
            "max_count":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":10,"title":"Max Count"},
            "ctx_size":{"type":["integer","null"],"default":3},
            "ref":{"type":"string","format":"uri-reference"}
        },
        "required":["repo_path"]
    }"#;
    assert!(
        check(
            r#"{"repo_path":"/repo","max_count":5,"ctx_size":null}"#,
            schema
        )
        .is_ok()
    );
    assert!(check(r#"{"repo_path":"/repo","max_count":"ten"}"#, schema).is_err());
    let err = check(r#"{"ctx_size":2}"#, schema).unwrap_err();
    assert!(err.contains("missing required"), "got: {err}");
}

/// @modelcontextprotocol/server-filesystem: `read_multiple_files`
/// requires a non-empty `paths` array (`minItems: 1`).
#[test]
fn test_real_filesystem_server_schema() {
    let schema = r#"{
        "type":"object",
        "properties":{
            "paths":{"type":"array","items":{"type":"string"},"minItems":1,"description":"List of file paths to read"}
        },
        "required":["paths"],
        "additionalProperties":false
    }"#;
    assert!(check(r#"{"paths":["/tmp/a"]}"#, schema).is_ok());
    let err = check(r#"{"paths":[]}"#, schema).unwrap_err();
    assert!(err.contains("minItems"), "got: {err}");
}

/// mcp-server-fetch: `format: "uri"` rides along as an annotation.
#[test]
fn test_real_fetch_server_schema() {
    let schema = r#"{
        "type":"object",
        "properties":{
            "url":{"type":"string","format":"uri","description":"URL to fetch"},
            "max_length":{"type":"integer","minimum":0,"maximum":1000000,"default":5000}
        },
        "required":["url"]
    }"#;
    assert!(check(r#"{"url":"https://example.com","max_length":100}"#, schema).is_ok());
    assert!(check(r#"{"url":"https://x","max_length":-1}"#, schema).is_err());
}
