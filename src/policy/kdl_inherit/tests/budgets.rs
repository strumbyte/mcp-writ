use super::*;

// ── inheritance traversal budgets ────────────────────────────────

#[test]
fn extends_chain_past_depth_limit_fails_closed() {
    let dir = make_test_dir("extends_depth");
    // Chain of extends past MAX_INHERIT_DEPTH — each level adds one
    // hop; the loader must refuse rather than recurse without bound.
    let depth = 40;
    for i in 0..depth {
        let next = format!("level_{}.kdl", i + 1);
        let body = if i + 1 == depth {
            "policy version=1\n".to_string()
        } else {
            format!("extends \"{next}\"\npolicy version=1\n")
        };
        std::fs::write(dir.join(format!("level_{i}.kdl")), body).unwrap();
    }
    let err = load_kdl_policy(&dir.join("level_0.kdl")).unwrap_err();
    assert!(err.to_string().contains("depth limit"), "got: {err}");
}

#[test]
fn include_fanout_past_file_limit_fails_closed() {
    let dir = make_test_dir("include_fanout");
    // One root including many files — acyclic, so the visited set
    // never trips; the file budget is what must refuse it.
    let mut root = String::new();
    for i in 0..300 {
        std::fs::write(dir.join(format!("inc_{i}.kdl")), "policy version=1\n").unwrap();
        root.push_str(&format!("include \"inc_{i}.kdl\"\n"));
    }
    root.push_str("policy version=1\n");
    std::fs::write(dir.join("root.kdl"), root).unwrap();
    let err = load_kdl_policy(&dir.join("root.kdl")).unwrap_err();
    assert!(err.to_string().contains("file limit"), "got: {err}");
}

#[test]
fn oversized_policy_file_fails_closed() {
    let dir = make_test_dir("oversized_policy");
    let mut body = String::from("policy version=1\ndefaults {\n  filesystem {\n");
    while body.len() as u64 <= crate::policy::MAX_POLICY_FILE_BYTES {
        body.push_str("    allow \"/pad\" mode=\"read\"\n");
    }
    body.push_str("  }\n}\n");
    std::fs::write(dir.join("big.kdl"), body).unwrap();
    let err = load_kdl_policy(&dir.join("big.kdl")).unwrap_err();
    assert!(err.to_string().contains("exceeds the"), "got: {err}");
}
