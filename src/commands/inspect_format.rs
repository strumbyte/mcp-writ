//! Inspect output extensions that reference Legislator types.
//!
//! `inspector::profile` owns the `CapabilityProfile` JSON/KDL body; the
//! `project_hints` and `source_tools` members depend on Legislator types
//! (`ProjectHint`, `ToolCapability`), which the Inspector layer must not
//! import. These wrappers append the Legislator-dependent members through
//! the `format_json_internal` extras hook.

use crate::inspector::profile::CapabilityProfile;
use crate::legislator::project_hints::ProjectHint;
use crate::legislator::sinks::ToolCapability;

/// Outputs the JSON literal `null`.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Outputs a boolean literal in JSON.
struct BoolLiteral(bool);

impl nojson::DisplayJson for BoolLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// `project_hints` member body for the inspect JSON document.
fn write_project_hints(
    ph: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    hint: &ProjectHint,
) -> std::fmt::Result {
    ph.member("project_type", hint.project_type.to_string().as_str())?;
    ph.member("confidence_summary", hint.confidence_summary.as_str())?;
    ph.member(
        "entry_points",
        nojson::array(|a| {
            for ep in &hint.entry_points {
                a.element(ep.as_str())?;
            }
            Ok(())
        }),
    )?;
    ph.member(
        "detected_permissions",
        nojson::array(|a| {
            for p in &hint.detected_permissions {
                a.element(nojson::object(|o| {
                    o.member("permission", p.permission.as_str())?;
                    o.member("confidence", p.confidence.as_str())?;
                    o.member("source", p.source.to_string().as_str())?;
                    o.member("evidence", p.evidence.as_str())
                }))?;
            }
            Ok(())
        }),
    )
}

/// `source_tools` member body for the inspect JSON document.
fn write_source_tools(
    a: &mut nojson::JsonArrayFormatter<'_, '_, '_>,
    tools: &[ToolCapability],
) -> std::fmt::Result {
    for t in tools {
        a.element(nojson::object(|o| {
            o.member("tool_name", t.tool_name.as_str())?;
            o.member(
                "permissions",
                nojson::array(|pa| {
                    for p in &t.permissions {
                        pa.element(p.as_str())?;
                    }
                    Ok(())
                }),
            )?;
            o.member("bound", BoolLiteral(t.bound))?;
            o.member(
                "audit_risks",
                nojson::array(|ra| {
                    for r in &t.audit_risks {
                        ra.element(r.as_str())?;
                    }
                    Ok(())
                }),
            )?;
            match &t.warning {
                Some(w) => o.member("warning", w.as_str())?,
                None => o.member("warning", &JsonNull)?,
            };
            Ok(())
        }))?;
    }
    Ok(())
}

/// Format a `CapabilityProfile` and its associated `ProjectHint` as a single valid JSON document.
pub(crate) fn format_json_with_project(profile: &CapabilityProfile, hint: &ProjectHint) -> String {
    crate::inspector::profile::format_json_internal(profile, &|f| {
        f.member(
            "project_hints",
            nojson::object(|ph| write_project_hints(ph, hint)),
        )
    })
}

/// Inspect JSON with optional project hints and interpreter `source_tools`.
pub(crate) fn format_json_with_extras(
    profile: &CapabilityProfile,
    hint: Option<&ProjectHint>,
    source_tools: Option<&[ToolCapability]>,
) -> String {
    crate::inspector::profile::format_json_internal(profile, &|f| {
        if let Some(h) = hint {
            f.member(
                "project_hints",
                nojson::object(|ph| write_project_hints(ph, h)),
            )?;
        }
        if let Some(tools) = source_tools {
            f.member(
                "source_tools",
                nojson::array(|a| write_source_tools(a, tools)),
            )?;
        }
        Ok(())
    })
}

/// Format a `CapabilityProfile` along with `ProjectHint` as a single valid KDL document.
pub(crate) fn format_kdl_with_project(profile: &CapabilityProfile, hint: &ProjectHint) -> String {
    let mut out = crate::inspector::profile::format_kdl(profile);
    out.push_str("\nproject_hints {\n");
    out.push_str(&format!(
        "    project_type \"{}\"\n",
        crate::termutil::escape_kdl_string(&hint.project_type.to_string())
    ));
    out.push_str(&format!(
        "    confidence_summary \"{}\"\n",
        crate::termutil::escape_kdl_string(hint.confidence_summary.as_str())
    ));
    if !hint.entry_points.is_empty() {
        let eps: Vec<String> = hint
            .entry_points
            .iter()
            .map(|ep| format!("\"{}\"", crate::termutil::escape_kdl_string(ep)))
            .collect();
        out.push_str(&format!("    entry_points {}\n", eps.join(" ")));
    }
    if !hint.detected_permissions.is_empty() {
        out.push_str("    detected_permissions {\n");
        for p in &hint.detected_permissions {
            out.push_str(&format!(
                "        permission \"{}\" confidence=\"{}\" source=\"{}\" evidence=\"{}\"\n",
                crate::termutil::escape_kdl_string(p.permission.as_str()),
                crate::termutil::escape_kdl_string(p.confidence.as_str()),
                crate::termutil::escape_kdl_string(&p.source.to_string()),
                crate::termutil::escape_kdl_string(&p.evidence)
            ));
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::elf_parser::RiskCategory;
    use crate::inspector::profile::test_support::make_profile;
    use crate::inspector::slicer::Resolution;

    #[test]
    fn test_format_json_with_project_valid() {
        let profile = make_profile(
            vec!["libc.so.6"],
            vec![("socket", RiskCategory::Network)],
            vec![(0x1000, Some(1), Some("write"), Resolution::Resolved)],
            vec!["https://example.com"],
            vec!["/etc/passwd"],
            vec!["HOME"],
            false,
        );
        let hint = crate::legislator::project_hints::ProjectHint {
            project_type: crate::legislator::project_hints::ProjectType::NodeJs,
            detected_permissions: vec![crate::legislator::project_hints::PermissionHint {
                permission: crate::legislator::heuristics::Permission::FileRead,
                confidence: crate::legislator::heuristics::Confidence::High,
                source: crate::legislator::project_hints::HintSource::SourceImport,
                evidence: "fs".to_string(),
            }],
            entry_points: vec!["index.js".to_string()],
            confidence_summary: crate::legislator::heuristics::Confidence::High,
        };
        let json_str = format_json_with_project(&profile, &hint);

        // Output must be valid JSON parseable by standard JSON parsers
        let parsed = nojson::RawJson::parse(&json_str);
        assert!(
            parsed.is_ok(),
            "JSON with project hints should be valid JSON: {json_str}"
        );
        let raw = parsed.unwrap();
        let val = raw.value();
        assert!(val.to_member("risk_score").is_ok());
        assert!(val.to_member("project_hints").is_ok());
    }

    #[test]
    fn test_format_json_source_tools() {
        let profile = CapabilityProfile::empty();
        let tools = vec![crate::legislator::sinks::ToolCapability {
            tool_name: "read_file".into(),
            permissions: vec![crate::legislator::heuristics::Permission::NetworkOutbound],
            bound: true,
            audit_risks: vec![],
            warning: None,
        }];
        let json_str = format_json_with_extras(&profile, None, Some(&tools));
        let parsed = nojson::RawJson::parse(&json_str);
        assert!(parsed.is_ok(), "{json_str}");
        let raw = parsed.unwrap();
        assert!(raw.value().to_member("source_tools").is_ok());
        assert!(json_str.contains("read_file"));
        assert!(json_str.contains("network:outbound"));
        let native = crate::inspector::profile::format_json(&profile);
        assert!(
            !native.contains("source_tools"),
            "native ELF JSON must omit source_tools when unused"
        );
    }
}
