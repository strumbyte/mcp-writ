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

// ── PR-03 differential: current vs frozen HEAD classification ─────

fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn assert_same_targets(
    want: &super::super::targets::ExtractedTargets,
    got: &super::super::targets::ExtractedTargets,
    ctx: String,
) {
    assert_eq!(want.paths, got.paths, "paths diverged: {ctx}");
    assert_eq!(want.urls, got.urls, "urls diverged: {ctx}");
    assert_eq!(want.hosts, got.hosts, "hosts diverged: {ctx}");
    assert_eq!(
        want.unclassified, got.unclassified,
        "unclassified diverged: {ctx}"
    );
    fn nc(t: &super::super::targets::ExtractedTargets) -> Vec<(&str, &str)> {
        t.noncanonical
            .iter()
            .map(|n| (n.raw.as_str(), n.normalized.as_str()))
            .collect()
    }
    assert_eq!(nc(want), nc(got), "noncanonical diverged: {ctx}");
    assert_eq!(want.truncated, got.truncated, "truncated diverged: {ctx}");
}

/// Representative key vocabulary: exact/suffixed path fields, network
/// fields, declared payload fields, and unrecognized names.
const DIFF_KEYS: &[&str] = &[
    "path",
    "File",
    "CWD",
    "source",
    "output",
    "dir",
    "target",
    "repo_path",
    "outputPath",
    "output_paths",
    "jsonPath",
    "json_path",
    "xPath",
    "configXPath",
    "indexPath",
    "url",
    "host",
    "hostname",
    "server",
    "addr",
    "ip_address",
    "endpoint",
    "upstream",
    "socket",
    "domain",
    "content",
    "text",
    "command",
    "query",
    "note",
    "prompt",
    "args",
    "frobnicate",
    "x-custom",
    "n3",
    "PathX",
    "hostfile",
    "",
];

/// Every (key, value) pair in the shared corpus must extract the same
/// targets under the PR-03 fast paths as under the frozen HEAD body —
/// same slots, same spellings, same noncanonical records.
#[test]
fn pr03_classification_matches_reference() {
    for key in DIFF_KEYS {
        for value in crate::testutil::argument_classification_corpus() {
            let line = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
                 \"params\":{{\"name\":\"t\",\"arguments\":{{{}:{}}}}}}}",
                json_quote(key),
                json_quote(&value)
            );
            let json = nojson::RawJson::parse(&line).unwrap();
            let want = super::super::targets::reference::collect(&json);
            let got = super::super::targets::collect_argument_targets(&json);
            assert_same_targets(&want, &got, format!("key={key:?} value={value:?}"));
        }
    }
}

/// Composite frames: many fields share the per-request dedup/budget
/// state — nested containers, the same spelling under different slots,
/// `inputResponses`, and large opaque payloads.
#[test]
fn pr03_classification_matches_reference_composite() {
    let blob = "A".repeat(65536);
    let frames = [
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\
             \"name\":\"t\",\"arguments\":{{\
             \"content\":{b},\"note\":{b},\"frobnicate\":{b},\
             \"path\":\"plain-token\",\"host\":\"plain-token\",\
             \"x\":\"/etc/passwd\",\"host2\":\"example.com\",\
             \"list\":[\"a\",\"b/c\",{b},\"/w/.ssh/id_rsa\"],\
             \"nested\":{{\"inner\":{{\"deep\":\"value\"}}}}\
             }},\"inputResponses\":{{\"r1\":{b},\"r2\":\"/etc/passwd\",\"r3\":\"plain-token\"}}\
             }}}}",
            b = json_quote(&blob)
        ),
        // Selector-looking values under declared payload keys still hit
        // the overlay; duplicates across slots share dedup state.
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\
             \"name\":\"t\",\"arguments\":{{\
             \"content\":\"/etc/passwd\",\"text\":\"/etc/passwd\",\
             \"path\":\".env\",\"prompt\":\".env\",\
             \"url\":\"https://example.com\",\"host\":\"https://example.com\"\
             }}}}}}"
        ),
        // A bare-name spelling under a suffixed path key, beside
        // JSONPath-expression values that must not classify as paths.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"jsonPath":"$.items[0]","outputJsonPath":"/data/out","repo_path":"build-output","xPath":"a/b"}}}"#.to_string(),
    ];
    for (i, line) in frames.iter().enumerate() {
        let json = nojson::RawJson::parse(line).unwrap();
        let want = super::super::targets::reference::collect(&json);
        let got = super::super::targets::collect_argument_targets(&json);
        assert_same_targets(&want, &got, format!("composite frame {i}"));
    }
}
