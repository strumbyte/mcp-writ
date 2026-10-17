use super::*;

fn findings(schema: &str) -> Vec<String> {
    unsupported_schema_findings(schema)
}

#[test]
fn test_scan_supported_schema_clean() {
    assert!(
        findings(r#"{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}"#)
            .is_empty()
    );
    assert!(findings(r##"{"type":["string","null"],"anyOf":[{"const":"x"}],"minItems":1,"maxItems":4,"uniqueItems":true,"multipleOf":0.5,"format":"uri","oneOf":[true],"properties":{"a":{}},"allOf":[{"$ref":"#/properties/a"}]}"##).is_empty());
    assert!(findings("true").is_empty());
    assert!(findings("false").is_empty());
}

#[test]
fn test_scan_unsupported_keywords_flagged() {
    let f = findings(r#"{"type":"object","patternProperties":{"^v":{}},"not":{}}"#);
    assert!(
        f.iter().any(|m| m.contains("patternProperties")),
        "expected patternProperties finding: {f:?}"
    );
    assert!(
        f.iter()
            .any(|m| m.contains("unsupported schema keyword 'not'")),
        "expected 'not' finding: {f:?}"
    );
}

#[test]
fn test_scan_nested_unsupported_keyword_flagged() {
    let f = findings(r#"{"type":"object","properties":{"x":{"items":{"if":{},"then":{}}}}}"#);
    assert!(
        f.iter().any(|m| m.contains("'if'") && m.contains("items")),
        "nested keyword under items flagged: {f:?}"
    );
    let f = findings(r#"{"anyOf":[{"contains":{}}]}"#);
    assert!(
        f.iter().any(|m| m.contains("'contains'")),
        "anyOf branch: {f:?}"
    );
}

#[test]
fn test_scan_data_positions_not_flagged() {
    // Schema-looking members inside enum/const/default are data.
    assert!(findings(r#"{"enum":[{"patternProperties":{"x":1}}],"default":{"if":1}}"#).is_empty());
    assert!(findings(r#"{"const":{"multipleOf":2}}"#).is_empty());
}

#[test]
fn test_scan_invalid_json_flagged() {
    assert!(!findings("{not json").is_empty());
    assert!(!findings("[1,2]").is_empty());
}

#[test]
fn test_scan_shape_errors_flagged() {
    assert!(!findings(r#"{"minItems":-1}"#).is_empty());
    assert!(!findings(r#"{"minItems":1.5}"#).is_empty());
    assert!(!findings(r#"{"multipleOf":0}"#).is_empty());
    assert!(!findings(r#"{"multipleOf":-2}"#).is_empty());
    assert!(findings(r#"{"multipleOf":1e-5000}"#).is_empty());
    // A numeric-looking string is still not a number — flagged.
    assert!(!findings(r#"{"multipleOf":"2"}"#).is_empty());
    assert!(!findings(r#"{"type":"strng"}"#).is_empty());
    assert!(!findings(r#"{"type":[]}"#).is_empty());
    assert!(!findings(r#"{"type":["string",5]}"#).is_empty());
    // Every union member is validated, not just up to the first match.
    assert!(!findings(r#"{"type":["string","bogus"]}"#).is_empty());
    assert!(!findings(r#"{"anyOf":[]}"#).is_empty());
    assert!(!findings(r#"{"anyOf":{}}"#).is_empty());
    assert!(!findings(r#"{"required":"x"}"#).is_empty());
    assert!(!findings(r#"{"required":[1]}"#).is_empty());
    assert!(!findings(r#"{"pattern":123}"#).is_empty());
    assert!(!findings(r#"{"pattern":"[a-"}"#).is_empty());
    assert!(!findings(r#"{"items":[{"type":"string"}]}"#).is_empty());
    assert!(!findings(r#"{"additionalProperties":5}"#).is_empty());
    assert!(!findings(r#"{"uniqueItems":"yes"}"#).is_empty());
    assert!(!findings(r#"{"format":5}"#).is_empty());
}

#[test]
fn test_scan_ref_local_and_external() {
    assert!(
        findings(r##"{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}"##).is_empty(),
        "local $defs ref is supported"
    );
    assert!(
        findings(r##"{"$ref":"#"}"##).is_empty(),
        "root self-reference is supported"
    );
    let f = findings(r#"{"$ref":"https://example.com/s.json"}"#);
    assert!(f.iter().any(|m| m.contains("$ref")), "external $ref: {f:?}");
    let f = findings(r##"{"$ref":"#/missing"}"##);
    assert!(
        f.iter().any(|m| m.contains("unresolvable")),
        "missing target: {f:?}"
    );
    let f = findings(r##"{"properties":{"x":{"$ref":"#/properties/x"}}}"##);
    assert!(f.is_empty(), "recursive $ref terminates: {f:?}");
}

#[test]
fn test_scan_member_names_escaped_in_visited() {
    // Member "a" is scanned first; under an unescaped scheme its `items`
    // subschema would claim the visited key `#/$defs/a/items`, hiding
    // the real member "a/items" and whatever it contains.
    let f = findings(r##"{"$defs":{"a":{"items":true},"a/items":{"not":{}}}}"##);
    assert!(
        f.iter().any(|m| m.contains("'not'")),
        "member with '/' must not be hidden by a sibling's ptr: {f:?}"
    );
    assert!(
        f.iter().any(|m| m.contains("a~1items")),
        "finding ptr reports the escaped segment: {f:?}"
    );
    // …and the mirror image: the `items` subschema keeps its own key.
    let f = findings(r##"{"$defs":{"a":{"items":{"not":{}}},"a/items":true}}"##);
    assert!(
        f.iter().any(|m| m.contains("'not'")),
        "items subschema must not be hidden by a '/' member: {f:?}"
    );
    // Same collision class under `properties`.
    let f = findings(r##"{"properties":{"a":{"items":true},"a/items":{"not":{}}}}"##);
    assert!(
        f.iter().any(|m| m.contains("properties/a~1items")),
        "properties member with '/' is scanned: {f:?}"
    );
}

#[test]
fn test_scan_ref_target_scanned_for_keywords() {
    let f = findings(r##"{"$defs":{"x":{"minProperties":1}},"$ref":"#/$defs/x"}"##);
    assert!(
        f.iter().any(|m| m.contains("minProperties")),
        "unsupported keyword under a $ref target is found: {f:?}"
    );
}

#[test]
fn test_scan_depth_limit() {
    let mut schema = String::from("true");
    for _ in 0..(MAX_SCHEMA_DEPTH as usize + 8) {
        schema = format!(r#"{{"items":{schema}}}"#);
    }
    let f = findings(&schema);
    assert!(
        f.iter().any(|m| m.contains("depth limit")),
        "deep nesting: {f:?}"
    );
}

#[test]
fn test_scan_findings_capped() {
    // Every member unknown → findings bounded by MAX_FINDINGS.
    let members = (0..40)
        .map(|i| format!(r#""zzz{i}":1"#))
        .collect::<Vec<_>>()
        .join(",");
    let f = findings(&format!("{{{members}}}"));
    assert_eq!(f.len(), MAX_FINDINGS, "findings capped: {f:?}");
}

#[test]
fn test_resolve_local_ref_pointers() {
    let json = RawJson::parse(
        r##"{"defs":{"a b":{"type":"integer"},"t/s":{"type":"string"},"~x":{"type":"boolean"}},"arr":[1,{"type":"null"}]}"##,
    )
    .unwrap();
    let root = json.value();
    assert_eq!(
        resolve_local_ref(root, "#/defs/a%20b").unwrap().kind(),
        JsonValueKind::Object
    );
    assert_eq!(
        resolve_local_ref(root, "#/defs/t~1s").unwrap().kind(),
        JsonValueKind::Object
    );
    assert_eq!(
        resolve_local_ref(root, "#/defs/~0x").unwrap().kind(),
        JsonValueKind::Object
    );
    assert!(resolve_local_ref(root, "#/arr/1").is_ok());
    assert!(resolve_local_ref(root, "#/arr/9").is_err());
    assert!(resolve_local_ref(root, "#/arr/x").is_err());
    assert!(resolve_local_ref(root, "#/defs/a%20b/0").is_err());
}
