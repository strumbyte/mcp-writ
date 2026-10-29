use super::*;

fn tool(name: &str, description: &str, schema: Option<&str>) -> ToolDefinition {
    let mut t = ToolDefinition::new(name, description);
    t.input_schema = schema.map(str::to_string);
    t
}

fn benign_read_file() -> ToolDefinition {
    tool(
        "read_file",
        "Read a file from disk by path and return its contents.",
        Some(r#"{"type":"object","properties":{"path":{"type":"string"}}}"#),
    )
}

fn findings_for(t: ToolDefinition) -> Vec<ManifestFinding> {
    scan_manifest(&[t])
}

fn has_rule(findings: &[ManifestFinding], rule: ManifestRule) -> bool {
    findings.iter().any(|f| f.rule == rule)
}
mod blocking;
mod collisions;
mod fail_on_threshold_tests;
mod first_seen_hash_tests;
mod icons_paths;
mod injection;
