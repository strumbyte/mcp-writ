//! Generic JSON Schema walking helpers for the manifest detectors:
//! string-leaf collection, `properties` enumeration, property-key matching,
//! and URI hints. CC-specific judgement stays with the detectors.

pub(crate) const MAX_SCHEMA_STRING_DEPTH: usize = 64;

pub(crate) fn schema_string_texts(schema: &str) -> Vec<String> {
    match nojson::RawJson::parse(schema) {
        Ok(json) => {
            let mut out = Vec::new();
            collect_json_strings(json.value(), &mut out, 0);
            out
        }
        Err(_) => vec![schema.to_string()],
    }
}

pub(crate) fn collect_json_strings(
    val: nojson::RawJsonValue<'_, '_>,
    out: &mut Vec<String>,
    depth: usize,
) {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::String => {
            if let Ok(s) = val.to_unquoted_string_str() {
                out.push(s.into_owned());
            }
        }
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    if let Ok(key) = k.to_unquoted_string_str() {
                        out.push(key.into_owned());
                    }
                    collect_json_strings(v, out, depth + 1);
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for item in arr {
                    collect_json_strings(item, out, depth + 1);
                }
            }
        }
        nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => {}
    }
}

pub(crate) fn json_key_name(key: nojson::RawJsonValue<'_, '_>) -> Option<String> {
    key.to_unquoted_string_str().ok().map(|s| s.into_owned())
}

pub(crate) fn for_each_schema_property(
    val: nojson::RawJsonValue<'_, '_>,
    depth: usize,
    visit: &mut impl FnMut(&str, nojson::RawJsonValue<'_, '_>),
) {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            let Ok(obj) = val.to_object() else {
                return;
            };
            if let Some(props) = val.to_member("properties").ok().and_then(|m| m.optional())
                && let Ok(props_obj) = props.to_object()
            {
                for (k, v) in props_obj {
                    if let Some(name) = json_key_name(k) {
                        visit(&name, v);
                        for_each_schema_property(v, depth + 1, visit);
                    }
                }
            }
            for (k, v) in obj {
                let Some(key) = json_key_name(k) else {
                    continue;
                };
                if key.eq_ignore_ascii_case("properties") {
                    continue;
                }
                match key.as_str() {
                    "oneOf" | "anyOf" | "allOf" | "prefixItems" => {
                        if let Ok(arr) = v.to_array() {
                            for item in arr {
                                for_each_schema_property(item, depth + 1, visit);
                            }
                        }
                    }
                    "$defs"
                    | "definitions"
                    | "items"
                    | "additionalProperties"
                    | "not"
                    | "if"
                    | "then"
                    | "else"
                    | "contains"
                    | "propertyNames"
                    | "unevaluatedProperties" => {
                        for_each_schema_property(v, depth + 1, visit);
                    }
                    "dependentSchemas" => {
                        if let Ok(dep) = v.to_object() {
                            for (_, schema) in dep {
                                for_each_schema_property(schema, depth + 1, visit);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for item in arr {
                    for_each_schema_property(item, depth + 1, visit);
                }
            }
        }
        nojson::JsonValueKind::String
        | nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => {}
    }
}

fn schema_property_names(schema: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(schema) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for_each_schema_property(json.value(), 0, &mut |name, _| {
        names.push(name.to_string());
    });
    names
}

pub(crate) fn schema_has_named_property(schema: &str, names: &[&str]) -> bool {
    schema_property_names(schema)
        .iter()
        .any(|n| names.iter().any(|want| n.eq_ignore_ascii_case(want)))
}

pub(crate) fn schema_property_keys(schema: &str) -> Vec<String> {
    if schema.is_empty() {
        return Vec::new();
    }
    match nojson::RawJson::parse(schema) {
        Ok(json) => {
            let mut out = Vec::new();
            collect_property_keys(json.value(), &mut out, 0);
            out
        }
        Err(_) => Vec::new(),
    }
}

fn collect_property_keys(val: nojson::RawJsonValue<'_, '_>, out: &mut Vec<String>, depth: usize) {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    let key = k.to_unquoted_string_str().ok().map(|s| s.into_owned());
                    if key.as_deref() == Some("properties") {
                        if let Ok(props) = v.to_object() {
                            for (pk, pv) in props {
                                if let Ok(prop_key) = pk.to_unquoted_string_str() {
                                    out.push(prop_key.into_owned());
                                }
                                collect_property_keys(pv, out, depth + 1);
                            }
                        }
                    } else {
                        collect_property_keys(v, out, depth + 1);
                    }
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for item in arr {
                    collect_property_keys(item, out, depth + 1);
                }
            }
        }
        nojson::JsonValueKind::Null
        | nojson::JsonValueKind::String
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => {}
    }
}

pub(crate) fn property_key_match(keys: &[String], wanted: &[&str]) -> bool {
    keys.iter()
        .any(|k| wanted.iter().any(|w| k.eq_ignore_ascii_case(w)))
}

pub(crate) fn property_schema_has_uri_hint(
    val: nojson::RawJsonValue<'_, '_>,
    depth: usize,
) -> bool {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return false;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Some(fmt) =
                schema_member(val, "format").and_then(|v| v.to_unquoted_string_str().ok())
                && fmt.eq_ignore_ascii_case("uri")
            {
                return true;
            }
            if json_subtree_has_https(val, depth) {
                return true;
            }
            for key in SCHEMA_NEST_KEYS {
                if let Some(nested) = schema_member(val, key)
                    && property_schema_has_uri_hint(nested, depth + 1)
                {
                    return true;
                }
            }
            for key in SCHEMA_MAP_KEYS {
                if let Some(map) = schema_member(val, key)
                    && let Ok(obj) = map.to_object()
                {
                    for (_, nested) in obj {
                        if property_schema_has_uri_hint(nested, depth + 1) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                arr.into_iter()
                    .any(|item| property_schema_has_uri_hint(item, depth + 1))
            } else {
                false
            }
        }
        nojson::JsonValueKind::String
        | nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => false,
    }
}

const SCHEMA_NEST_KEYS: &[&str] = &[
    "oneOf",
    "anyOf",
    "allOf",
    "not",
    "if",
    "then",
    "else",
    "items",
    "prefixItems",
    "additionalProperties",
    "contains",
    "propertyNames",
    "unevaluatedProperties",
];

const SCHEMA_MAP_KEYS: &[&str] = &["properties", "$defs", "definitions", "dependentSchemas"];

pub(crate) fn schema_member<'a, 'b>(
    val: nojson::RawJsonValue<'a, 'b>,
    name: &str,
) -> Option<nojson::RawJsonValue<'a, 'b>> {
    val.to_member(name).ok().and_then(|m| m.optional())
}

fn string_contains_https(val: nojson::RawJsonValue<'_, '_>) -> bool {
    val.to_unquoted_string_str()
        .ok()
        .is_some_and(|s| s.to_ascii_lowercase().contains("https://"))
}

fn json_subtree_has_https(val: nojson::RawJsonValue<'_, '_>, depth: usize) -> bool {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return false;
    }
    match val.kind() {
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                arr.into_iter()
                    .any(|item| json_subtree_has_https(item, depth + 1))
            } else {
                false
            }
        }
        nojson::JsonValueKind::Object => {
            if let Some(c) = schema_member(val, "const")
                && string_contains_https(c)
            {
                return true;
            }
            if let Some(en) = schema_member(val, "enum")
                && let Ok(arr) = en.to_array()
                && arr.into_iter().any(string_contains_https)
            {
                return true;
            }
            for key in SCHEMA_NEST_KEYS {
                if let Some(nested) = schema_member(val, key)
                    && json_subtree_has_https(nested, depth + 1)
                {
                    return true;
                }
            }
            for key in SCHEMA_MAP_KEYS {
                if let Some(map) = schema_member(val, key)
                    && let Ok(obj) = map.to_object()
                {
                    for (_, nested) in obj {
                        if json_subtree_has_https(nested, depth + 1) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        nojson::JsonValueKind::String
        | nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => false,
    }
}
