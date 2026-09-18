/// A single MCP tool definition extracted from a tools/list response.
///
/// Extra MCP fields are retained as raw JSON so first-seen can scan unknown
/// vendor keys. Forwarding rebuilds tools from the hash-v4 / scanned field set
/// only (unknown keys are dropped). Hash v4 pins the optional fields below;
/// missing keys are omitted from the canonical digest.
#[derive(Debug, Clone, Default)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub title: Option<String>,
    pub input_schema: Option<String>,
    pub output_schema: Option<String>,
    pub annotations_raw: Option<String>,
    pub icons_raw: Option<String>,
    pub execution_raw: Option<String>,
    pub meta_raw: Option<String>,
    /// Original tool object JSON. Used to scan unknown vendor keys.
    /// Never forwarded as-is; responses are rebuilt from verified fields.
    pub raw_json: Option<String>,
}

impl ToolDefinition {
    /// Minimal constructor for tests and generate-policy fixtures.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            ..Self::default()
        }
    }

    pub fn with_input_schema(mut self, schema: impl Into<String>) -> Self {
        self.input_schema = Some(schema.into());
        self
    }

    /// Advertised strings used by generate-policy heuristics / RIS.
    ///
    /// Includes `name`, `description`, `title`, `annotations`, `execution`,
    /// and `_meta`. `icons` is omitted so `icons[].src` URLs do not drive
    /// `side_effect` / network hints. Schema JSON stays on Layer 3.
    pub fn advertised_text(&self) -> String {
        let mut parts = vec![self.name.clone(), self.description.clone()];
        if let Some(title) = &self.title {
            parts.push(title.clone());
        }
        for extra in [
            self.annotations_raw.as_deref(),
            self.execution_raw.as_deref(),
            self.meta_raw.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            parts.push(extra.to_string());
        }
        parts.join("\n")
    }
}
