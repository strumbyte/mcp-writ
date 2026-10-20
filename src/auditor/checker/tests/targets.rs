// ── extract / dedup ─────────────────────────────────────────

#[test]
fn test_target_dedup_is_per_slot() {
    // Regression: deduplication used to key on the normalized string
    // alone. The same spelling classified under different keys lands in
    // different slots, and dropping the host copy on a value-only key
    // would let a destination skip the network verdict entirely.
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"path":"http://10.0.0.2/","host":"http://10.0.0.2/"}}}"#;
    let json = nojson::RawJson::parse(line).unwrap();
    let out = super::super::targets::collect_argument_targets(&json);
    assert!(
        out.urls.iter().any(|u| u == "http://10.0.0.2/"),
        "the path-key occurrence stays a URL target: {out:?}",
        out = out.urls
    );
    assert!(
        out.hosts.iter().any(|h| h == "http://10.0.0.2/"),
        "the host-key occurrence must still reach host checks: {:?}",
        out.hosts
    );
}

#[test]
fn test_target_dedup_keeps_unclassified_copy() {
    // A token under an unrecognized key is a possible undeclared
    // selector — it must survive in `unclassified` even when a path
    // field carries the same spelling (different slot, same string).
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"path":"not-a-selector","frobnicate":"not-a-selector"}}}"#;
    let json = nojson::RawJson::parse(line).unwrap();
    let out = super::super::targets::collect_argument_targets(&json);
    assert_eq!(out.paths, vec!["not-a-selector".to_string()]);
    assert_eq!(out.unclassified, vec!["not-a-selector".to_string()]);
}

#[test]
fn test_target_dedup_same_slot_still_collapses() {
    // Within one slot, repeated spellings still cost a single check —
    // the per-slot key must not reintroduce per-occurrence work.
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"host":["10.0.0.2:443","10.0.0.2:443"],"extra":{"host":"10.0.0.2:443"}}}}"#;
    let json = nojson::RawJson::parse(line).unwrap();
    let out = super::super::targets::collect_argument_targets(&json);
    assert_eq!(out.hosts, vec!["10.0.0.2:443".to_string()]);
}
