use crate::tool_def::ToolDefinition;

/// OS-level permission category inferred from tool definitions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    FileRead,
    FileWrite,
    NetworkOutbound,
    ProcessExec,
    DatabaseAccess,
    Unknown,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileRead => "file:read",
            Self::FileWrite => "file:write",
            Self::NetworkOutbound => "network:outbound",
            Self::ProcessExec => "process:exec",
            Self::DatabaseAccess => "database:access",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence level of the heuristic match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Schema inference only (lowest).
    Low = 0,
    /// Keyword partial match in name or description.
    Medium = 1,
    /// Exact tool name match (highest).
    High = 2,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Risk level associated with the inferred permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// The result of analyzing a single tool definition for its intent.
#[derive(Debug, Clone)]
pub struct IntentProfile {
    pub tool_name: String,
    pub required_permissions: Vec<Permission>,
    pub confidence: Confidence,
    pub risk_level: RiskLevel,
}

/// Analyze a single tool definition and infer its required permissions.
///
/// The analysis proceeds in three layers with decreasing confidence:
/// 1. **Exact name match** (High confidence) — well-known tool names
/// 2. **Keyword match** (Medium confidence) — keywords in advertised text
///    (`name`, `description`, `title`, annotations / execution / `_meta`;
///    not `icons[].src`)
/// 3. **Schema inference** (Low confidence) — argument names in input_schema
///
/// The highest confidence signal found determines the overall confidence level.
pub fn analyze_tool(tool: &ToolDefinition) -> IntentProfile {
    let name_lower = tool.name.to_lowercase();

    // Layer 1: Exact name match (High confidence)
    if let Some(profile) = match_exact_name(&tool.name, &name_lower) {
        return profile;
    }

    // Layer 2: Keyword match in advertised text (Medium confidence; not icons)
    if let Some(profile) = match_keywords(tool, &name_lower) {
        return profile;
    }

    // Layer 3: Schema inference (Low confidence)
    if let Some(profile) = match_schema(tool) {
        return profile;
    }

    // No signals found
    IntentProfile {
        tool_name: tool.name.clone(),
        required_permissions: vec![Permission::Unknown],
        confidence: Confidence::Low,
        risk_level: RiskLevel::Low,
    }
}

/// Analyze multiple tool definitions at once.
pub fn analyze_tools(tools: &[ToolDefinition]) -> Vec<IntentProfile> {
    tools.iter().map(analyze_tool).collect()
}

// ---------------------------------------------------------------------------
// Layer 1: Exact name match
// ---------------------------------------------------------------------------

/// Well-known tool name patterns mapped to permissions.
/// Each entry: (exact_name, permissions, risk_level)
const EXACT_NAME_RULES: &[(&str, &[Permission], RiskLevel)] = &[
    // File read
    ("read_file", &[Permission::FileRead], RiskLevel::Low),
    ("list_files", &[Permission::FileRead], RiskLevel::Low),
    ("list_directory", &[Permission::FileRead], RiskLevel::Low),
    ("get_file_info", &[Permission::FileRead], RiskLevel::Low),
    ("search_files", &[Permission::FileRead], RiskLevel::Low),
    // File write
    ("write_file", &[Permission::FileWrite], RiskLevel::Medium),
    ("delete_file", &[Permission::FileWrite], RiskLevel::High),
    (
        "create_directory",
        &[Permission::FileWrite],
        RiskLevel::Medium,
    ),
    (
        "move_file",
        &[Permission::FileRead, Permission::FileWrite],
        RiskLevel::Medium,
    ),
    (
        "copy_file",
        &[Permission::FileRead, Permission::FileWrite],
        RiskLevel::Medium,
    ),
    // Network
    (
        "fetch_url",
        &[Permission::NetworkOutbound],
        RiskLevel::Medium,
    ),
    (
        "http_request",
        &[Permission::NetworkOutbound],
        RiskLevel::Medium,
    ),
    (
        "download",
        &[Permission::NetworkOutbound],
        RiskLevel::Medium,
    ),
    ("curl", &[Permission::NetworkOutbound], RiskLevel::Medium),
    ("wget", &[Permission::NetworkOutbound], RiskLevel::Medium),
    // Process exec (Critical risk)
    (
        "execute_command",
        &[Permission::ProcessExec],
        RiskLevel::Critical,
    ),
    ("run_shell", &[Permission::ProcessExec], RiskLevel::Critical),
    ("exec", &[Permission::ProcessExec], RiskLevel::Critical),
    (
        "spawn_process",
        &[Permission::ProcessExec],
        RiskLevel::Critical,
    ),
    ("bash", &[Permission::ProcessExec], RiskLevel::Critical),
    // Database
    (
        "query_database",
        &[Permission::DatabaseAccess],
        RiskLevel::Medium,
    ),
    (
        "sql_execute",
        &[Permission::DatabaseAccess],
        RiskLevel::High,
    ),
];

fn match_exact_name(original_name: &str, name_lower: &str) -> Option<IntentProfile> {
    for &(pattern, perms, risk) in EXACT_NAME_RULES {
        if name_lower == pattern {
            return Some(IntentProfile {
                tool_name: original_name.to_string(),
                required_permissions: perms.to_vec(),
                confidence: Confidence::High,
                risk_level: risk,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Layer 2: Keyword match in name or description
// ---------------------------------------------------------------------------

/// Keyword patterns and associated permissions.
/// Each entry: (keyword, permission, risk_level)
const KEYWORD_RULES: &[(&str, Permission, RiskLevel)] = &[
    // File system keywords
    ("file", Permission::FileRead, RiskLevel::Low),
    ("path", Permission::FileRead, RiskLevel::Low),
    ("directory", Permission::FileRead, RiskLevel::Low),
    ("folder", Permission::FileRead, RiskLevel::Low),
    ("write", Permission::FileWrite, RiskLevel::Medium),
    ("delete", Permission::FileWrite, RiskLevel::High),
    ("remove", Permission::FileWrite, RiskLevel::High),
    ("create", Permission::FileWrite, RiskLevel::Medium),
    // Network keywords
    ("url", Permission::NetworkOutbound, RiskLevel::Medium),
    ("http", Permission::NetworkOutbound, RiskLevel::Medium),
    ("fetch", Permission::NetworkOutbound, RiskLevel::Medium),
    ("download", Permission::NetworkOutbound, RiskLevel::Medium),
    ("request", Permission::NetworkOutbound, RiskLevel::Medium),
    ("api", Permission::NetworkOutbound, RiskLevel::Medium),
    // Process keywords
    ("execute", Permission::ProcessExec, RiskLevel::Critical),
    ("command", Permission::ProcessExec, RiskLevel::Critical),
    ("shell", Permission::ProcessExec, RiskLevel::Critical),
    ("run", Permission::ProcessExec, RiskLevel::High),
    ("spawn", Permission::ProcessExec, RiskLevel::Critical),
    // Database keywords
    ("database", Permission::DatabaseAccess, RiskLevel::Medium),
    ("query", Permission::DatabaseAccess, RiskLevel::Medium),
    ("sql", Permission::DatabaseAccess, RiskLevel::High),
];

fn match_keywords(tool: &ToolDefinition, name_lower: &str) -> Option<IntentProfile> {
    let advertised_lower = tool.advertised_text().to_lowercase();

    let mut permissions = Vec::new();
    let mut max_risk = RiskLevel::Low;

    for &(keyword, ref perm, risk) in KEYWORD_RULES {
        if name_lower.contains(keyword) || advertised_lower.contains(keyword) {
            if !permissions.contains(perm) {
                permissions.push(perm.clone());
            }
            if risk > max_risk {
                max_risk = risk;
            }
        }
    }

    if permissions.is_empty() {
        return None;
    }

    Some(IntentProfile {
        tool_name: tool.name.clone(),
        required_permissions: permissions,
        confidence: Confidence::Medium,
        risk_level: max_risk,
    })
}

// ---------------------------------------------------------------------------
// Layer 3: Schema inference
// ---------------------------------------------------------------------------

/// Schema argument names mapped to permissions.
/// Each entry: (arg_name_substring, permission, risk_level)
const SCHEMA_ARG_RULES: &[(&str, Permission, RiskLevel)] = &[
    ("path", Permission::FileRead, RiskLevel::Low),
    ("file", Permission::FileRead, RiskLevel::Low),
    ("directory", Permission::FileRead, RiskLevel::Low),
    ("url", Permission::NetworkOutbound, RiskLevel::Medium),
    ("uri", Permission::NetworkOutbound, RiskLevel::Medium),
    ("endpoint", Permission::NetworkOutbound, RiskLevel::Medium),
    ("command", Permission::ProcessExec, RiskLevel::Critical),
    ("cmd", Permission::ProcessExec, RiskLevel::Critical),
    ("query", Permission::DatabaseAccess, RiskLevel::Medium),
    ("sql", Permission::DatabaseAccess, RiskLevel::High),
];

fn match_schema(tool: &ToolDefinition) -> Option<IntentProfile> {
    let schema_str = tool.input_schema.as_deref()?;

    let mut permissions = Vec::new();
    let mut max_risk = RiskLevel::Low;

    // Try to parse schema as JSON and extract property names
    let property_names = extract_property_names(schema_str);

    if !property_names.is_empty() {
        // Use parsed property names for matching
        for prop_name in &property_names {
            let prop_lower = prop_name.to_lowercase();
            for &(arg_name, ref perm, risk) in SCHEMA_ARG_RULES {
                if prop_lower.contains(arg_name) {
                    if !permissions.contains(perm) {
                        permissions.push(perm.clone());
                    }
                    if risk > max_risk {
                        max_risk = risk;
                    }
                }
            }
        }
    } else {
        // Fallback to substring search if JSON parsing fails
        let schema_lower = schema_str.to_lowercase();
        for &(arg_name, ref perm, risk) in SCHEMA_ARG_RULES {
            if schema_lower.contains(arg_name) {
                if !permissions.contains(perm) {
                    permissions.push(perm.clone());
                }
                if risk > max_risk {
                    max_risk = risk;
                }
            }
        }
    }

    if permissions.is_empty() {
        return None;
    }

    Some(IntentProfile {
        tool_name: tool.name.clone(),
        required_permissions: permissions,
        confidence: Confidence::Low,
        risk_level: max_risk,
    })
}

/// Maximum recursion depth when walking JSON schema trees.
const MAX_SCHEMA_DEPTH: usize = 16;

/// Extract property names from a JSON schema string.
/// Walks the "properties" object and nested objects to collect keys.
fn extract_property_names(schema_str: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(schema_str) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    collect_property_names(json.value(), &mut names, 0);
    names
}

/// Recursively collect property names from a parsed JSON value.
fn collect_property_names(
    value: nojson::RawJsonValue<'_, '_>,
    names: &mut Vec<String>,
    depth: usize,
) {
    if depth >= MAX_SCHEMA_DEPTH {
        return;
    }

    if let Ok(obj) = value.to_object() {
        // Check if this object has a "properties" member
        let has_props = value
            .to_member("properties")
            .ok()
            .and_then(|m| m.optional());
        if let Some(props_val) = has_props
            && let Ok(props_obj) = props_val.to_object()
        {
            for (key, val) in props_obj {
                if let Ok(key_str) = key.as_string_str() {
                    names.push(key_str.to_string());
                    // Recursively check nested objects
                    collect_property_names(val, names, depth + 1);
                }
            }
        } else {
            // Walk all values in the object
            for (_key, val) in obj {
                collect_property_names(val, names, depth + 1);
            }
        }
    } else if let Ok(arr) = value.to_array() {
        for item in arr {
            collect_property_names(item, names, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str, schema: Option<&str>) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: desc.to_string(),
            input_schema: schema.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    // --- Layer 1: Exact name match ---

    #[test]
    fn test_read_file_exact() {
        let t = tool("read_file", "Read a file from disk", None);
        let p = analyze_tool(&t);
        assert_eq!(p.tool_name, "read_file");
        assert_eq!(p.required_permissions, vec![Permission::FileRead]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_write_file_exact() {
        let t = tool("write_file", "Write content to a file", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::FileWrite]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_execute_command_critical_risk() {
        let t = tool("execute_command", "Execute a shell command", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::ProcessExec]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_fetch_url_exact() {
        let t = tool("fetch_url", "Fetch content from a URL", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::NetworkOutbound]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_query_database_exact() {
        let t = tool("query_database", "Run a database query", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::DatabaseAccess]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_delete_file_high_risk() {
        let t = tool("delete_file", "Delete a file", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::FileWrite]);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_exact_name_case_insensitive() {
        let t = tool("Read_File", "Read a file", None);
        let p = analyze_tool(&t);
        assert_eq!(p.confidence, Confidence::High);
        assert_eq!(p.required_permissions, vec![Permission::FileRead]);
    }

    // --- Layer 2: Keyword match ---

    #[test]
    fn test_keyword_in_name() {
        let t = tool("get_file_contents", "Get contents", None);
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::FileRead));
        assert_eq!(p.confidence, Confidence::Medium);
    }

    #[test]
    fn test_keyword_in_description() {
        let t = tool("custom_tool", "Downloads data from a remote URL", None);
        let p = analyze_tool(&t);
        assert!(
            p.required_permissions
                .contains(&Permission::NetworkOutbound)
        );
        assert_eq!(p.confidence, Confidence::Medium);
    }

    #[test]
    fn test_keyword_in_title_when_description_empty() {
        let mut t = tool("custom_tool", "", None);
        t.title = Some("Fetch URL from the remote host".into());
        let p = analyze_tool(&t);
        assert!(
            p.required_permissions
                .contains(&Permission::NetworkOutbound),
            "title 'fetch URL' must drive side_effect/RIS, got {:?}",
            p.required_permissions
        );
        assert_eq!(p.confidence, Confidence::Medium);
    }

    #[test]
    fn test_icon_src_http_does_not_imply_network() {
        let mut t = tool("custom_tool", "Adds two numbers", None);
        t.icons_raw = Some(r#"[{"src":"https://cdn.example/icon.png"}]"#.into());
        let p = analyze_tool(&t);
        assert_eq!(
            p.required_permissions,
            vec![Permission::Unknown],
            "icons[].src must not drive side_effect/network hints, got {:?}",
            p.required_permissions
        );
    }

    #[test]
    fn test_keyword_shell_in_description() {
        let t = tool("my_tool", "Runs a shell command on the server", None);
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::ProcessExec));
        assert_eq!(p.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_keyword_multiple_signals() {
        let t = tool("file_uploader", "Upload a file to a remote URL", None);
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::FileRead));
        assert!(
            p.required_permissions
                .contains(&Permission::NetworkOutbound)
        );
        assert_eq!(p.confidence, Confidence::Medium);
    }

    // --- Layer 3: Schema inference ---

    #[test]
    fn test_schema_path_argument() {
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}}}"#;
        let t = tool("custom_op", "", Some(schema));
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::FileRead));
        assert_eq!(p.confidence, Confidence::Low);
    }

    #[test]
    fn test_schema_url_argument() {
        let schema = r#"{"type":"object","properties":{"url":{"type":"string"}}}"#;
        let t = tool("do_something", "", Some(schema));
        let p = analyze_tool(&t);
        assert!(
            p.required_permissions
                .contains(&Permission::NetworkOutbound)
        );
        assert_eq!(p.confidence, Confidence::Low);
    }

    #[test]
    fn test_schema_command_argument() {
        let schema = r#"{"type":"object","properties":{"command":{"type":"string"}}}"#;
        let t = tool("action", "", Some(schema));
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::ProcessExec));
        assert_eq!(p.confidence, Confidence::Low);
        assert_eq!(p.risk_level, RiskLevel::Critical);
    }

    // --- Unknown / no signal ---

    #[test]
    fn test_unknown_tool_no_signals() {
        let t = tool("custom_tool", "Does something special", None);
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::Unknown]);
        assert_eq!(p.confidence, Confidence::Low);
        assert_eq!(p.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_unknown_tool_with_irrelevant_schema() {
        let schema = r#"{"type":"object","properties":{"count":{"type":"number"},"name":{"type":"string"}}}"#;
        let t = tool("custom_tool", "Does something", Some(schema));
        let p = analyze_tool(&t);
        assert_eq!(p.required_permissions, vec![Permission::Unknown]);
    }

    // --- Batch analysis ---

    #[test]
    fn test_analyze_tools_batch() {
        let tools = vec![
            tool("read_file", "Read a file", None),
            tool("execute_command", "Execute a command", None),
            tool("custom_tool", "Mystery tool", None),
        ];
        let profiles = analyze_tools(&tools);
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].confidence, Confidence::High);
        assert_eq!(profiles[1].risk_level, RiskLevel::Critical);
        assert_eq!(profiles[2].required_permissions, vec![Permission::Unknown]);
    }

    #[test]
    fn test_analyze_tools_empty() {
        let profiles = analyze_tools(&[]);
        assert!(profiles.is_empty());
    }

    // --- Confidence ordering ---

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    // --- Risk ordering ---

    #[test]
    fn test_risk_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    // --- Display impls ---

    #[test]
    fn test_permission_display() {
        assert_eq!(format!("{}", Permission::FileRead), "file:read");
        assert_eq!(format!("{}", Permission::ProcessExec), "process:exec");
    }

    // --- Layer priority: exact > keyword > schema ---

    #[test]
    fn test_exact_takes_priority_over_keyword() {
        // "read_file" matches exact rule AND keyword "file"
        // Should get High confidence (exact), not Medium (keyword)
        let t = tool("read_file", "Read a file from the filesystem", None);
        let p = analyze_tool(&t);
        assert_eq!(p.confidence, Confidence::High);
    }

    #[test]
    fn test_keyword_takes_priority_over_schema() {
        // Name contains "file" keyword AND schema has "path"
        // Should get Medium confidence (keyword), not Low (schema)
        let schema = r#"{"type":"object","properties":{"path":{"type":"string"}}}"#;
        let t = tool("my_file_tool", "", Some(schema));
        let p = analyze_tool(&t);
        assert_eq!(p.confidence, Confidence::Medium);
    }

    // --- Move/copy tools have dual permissions ---

    #[test]
    fn test_move_file_dual_permissions() {
        let t = tool("move_file", "Move a file", None);
        let p = analyze_tool(&t);
        assert!(p.required_permissions.contains(&Permission::FileRead));
        assert!(p.required_permissions.contains(&Permission::FileWrite));
        assert_eq!(p.confidence, Confidence::High);
    }
}
