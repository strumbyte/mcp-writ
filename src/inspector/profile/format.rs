use super::CapabilityProfile;
use super::score::{PROCESS_SYSCALLS, risk_level};
use crate::inspector::elf_parser::RiskCategory;
use crate::inspector::slicer::{Resolution, SyscallKind};
use crate::inspector::target::{AnalysisState, AnalysisStatus, ElfClass, MachOSlice};
use crate::legislator::sinks::ToolCapability;

/// One-line label for an `AnalysisState`: `status` plus `(reason — detail)`
/// when present.
fn state_label(state: &AnalysisState) -> String {
    let mut s = state.status.as_str().to_string();
    if let Some(r) = state.reason {
        s.push_str(&format!(" ({})", r.as_str()));
    }
    if let Some(d) = &state.detail {
        s.push_str(&format!(" — {}", crate::termutil::sanitize_for_terminal(d)));
    }
    s
}

/// One-line label for a Mach-O slice: `selected: <syscall state>` for the
/// analyzed slice, `skipped: <state>` otherwise.
fn slice_state_label(slice: &MachOSlice, syscall_state: &AnalysisState) -> String {
    if slice.selected {
        format!("selected: {}", state_label(syscall_state))
    } else {
        match &slice.state {
            Some(state) => format!("skipped: {}", state_label(state)),
            None => "skipped".to_string(),
        }
    }
}

/// Format a `CapabilityProfile` as a human-readable report.
pub fn format_human(profile: &CapabilityProfile) -> String {
    let mut out = String::new();

    out.push_str("=== Capability Profile ===\n");
    out.push_str(&format!(
        "Risk Score: {}/100 ({})\n",
        profile.risk_score,
        risk_level(profile.risk_score)
    ));

    // Target + analysis state. An empty syscall list below is only
    // meaningful when this says `analyzed`.
    let t = &profile.analysis.target;
    let class = match t.elf_class {
        Some(ElfClass::Elf64) => " elf64",
        Some(ElfClass::Elf32) => " elf32",
        None => "",
    };
    let machine = t
        .machine
        .map(|m| format!(" machine={m}"))
        .unwrap_or_default();
    let slice = t
        .slice
        .as_deref()
        .map(|s| format!(" slice=\"{s}\""))
        .unwrap_or_default();
    let platform = t
        .platform
        .map(|p| format!(" platform={}", p.as_str()))
        .unwrap_or_default();
    out.push_str(&format!(
        "Target: {} {}{}{}{}{} abi={} endianness={}\n",
        t.format.as_str(),
        t.isa.as_str(),
        class,
        machine,
        slice,
        platform,
        t.abi.as_str(),
        t.endianness.as_str(),
    ));
    out.push_str(&format!(
        "Analysis: symbols={} strings={} syscalls={}\n",
        state_label(&profile.analysis.symbols),
        state_label(&profile.analysis.strings),
        state_label(&profile.analysis.syscalls),
    ));

    // Mach-O slices: each slice keeps its own target and analysis state —
    // a fat binary must never look validated end to end when only its
    // arm64 slice was decoded.
    if !t.slices.is_empty() {
        out.push_str(&format!("Slices ({}):\n", t.slices.len()));
        for s in &t.slices {
            out.push_str(&format!(
                "  - {} cputype={:#x} cpusubtype={:#x} offset={:#x} size={:#x} [{}]\n",
                crate::termutil::sanitize_for_terminal(&s.arch),
                s.cputype,
                s.cpusubtype,
                s.offset,
                s.size,
                slice_state_label(s, &profile.analysis.syscalls),
            ));
        }
    }

    // Libraries
    out.push_str(&format!(
        "\nLibraries ({}):\n",
        profile.symbols.libraries.len()
    ));
    if profile.symbols.libraries.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for lib in &profile.symbols.libraries {
            out.push_str(&format!(
                "  - {}\n",
                crate::termutil::sanitize_for_terminal(lib)
            ));
        }
    }

    // Detected Syscalls
    out.push_str(&format!(
        "\nDetected Syscalls ({}):\n",
        profile.syscalls.len()
    ));
    if profile.syscalls.is_empty() {
        match profile.analysis.syscalls.status {
            AnalysisStatus::Analyzed => out.push_str("  (none)\n"),
            _ => out.push_str(&format!(
                "  (not analyzed: {})\n",
                state_label(&profile.analysis.syscalls)
            )),
        }
    } else {
        for sc in &profile.syscalls {
            let name = crate::termutil::sanitize_for_terminal(
                sc.syscall_name.as_deref().unwrap_or("unknown"),
            );
            let num = match sc.syscall_number {
                Some(n) => n.to_string(),
                None => "?".to_string(),
            };
            let res = match sc.resolution {
                Resolution::Resolved => "Resolved".to_string(),
                Resolution::Unresolved => match sc.resolution_detail {
                    Some(d) => format!("Unresolved: {d}"),
                    None => "Unresolved".to_string(),
                },
                Resolution::Ambiguous => "Ambiguous".to_string(),
            };
            let kind_marker = match sc.kind {
                SyscallKind::MachTrap => " (mach_trap)",
                SyscallKind::Unknown => " (entry kind unknown)",
                SyscallKind::Unix => "",
            };
            let risk_marker = if sc
                .syscall_name
                .as_deref()
                .is_some_and(|n| PROCESS_SYSCALLS.contains(&n))
            {
                " ⚠ HIGH RISK"
            } else {
                ""
            };
            out.push_str(&format!(
                "  - {name} ({num}) [{res}]{kind_marker}{risk_marker}\n"
            ));
        }
    }

    // Strings
    out.push_str("\nStrings:\n");
    out.push_str(&format!(
        "  URLs ({}): {}\n",
        profile.strings.urls.len(),
        if profile.strings.urls.is_empty() {
            "(none)".to_string()
        } else {
            profile
                .strings
                .urls
                .iter()
                .map(|u| crate::termutil::sanitize_for_terminal(u))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    out.push_str(&format!(
        "  Paths ({}): {}\n",
        profile.strings.paths.len(),
        if profile.strings.paths.is_empty() {
            "(none)".to_string()
        } else {
            profile
                .strings
                .paths
                .iter()
                .map(|p| crate::termutil::sanitize_for_terminal(p))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    out.push_str(&format!(
        "  Env Vars ({}): {}\n",
        profile.strings.env_vars.len(),
        if profile.strings.env_vars.is_empty() {
            "(none)".to_string()
        } else {
            profile
                .strings
                .env_vars
                .iter()
                .map(|e| crate::termutil::sanitize_for_terminal(e))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));

    // Risk Summary
    out.push_str("\nRisk Summary:\n");
    if profile.risk_summary.is_empty() {
        out.push_str("  (no risk indicators detected)\n");
    } else {
        for line in &profile.risk_summary {
            out.push_str(&format!(
                "  - {}\n",
                crate::termutil::sanitize_for_terminal(line)
            ));
        }
    }

    out
}

/// Outputs a raw numeric literal in JSON.
struct NumLiteral(u64);

impl nojson::DisplayJson for NumLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// Outputs a raw *signed* numeric literal in JSON (Mach trap numbers are
/// negative).
struct INumLiteral(i64);

impl nojson::DisplayJson for INumLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// Outputs a raw u32 literal in JSON.
struct U32Literal(u32);

impl nojson::DisplayJson for U32Literal {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

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

/// Format a `CapabilityProfile` as JSON using nojson (no serde).
pub fn format_json(profile: &CapabilityProfile) -> String {
    format_json_internal(profile, None, None)
}

/// Format a `CapabilityProfile` and its associated `ProjectHint` as a single valid JSON document.
pub fn format_json_with_project(
    profile: &CapabilityProfile,
    hint: &crate::legislator::project_hints::ProjectHint,
) -> String {
    format_json_internal(profile, Some(hint), None)
}

/// Inspect JSON with optional project hints and interpreter `source_tools`.
pub fn format_json_with_extras(
    profile: &CapabilityProfile,
    hint: Option<&crate::legislator::project_hints::ProjectHint>,
    source_tools: Option<&[ToolCapability]>,
) -> String {
    format_json_internal(profile, hint, source_tools)
}

/// Serialize one `AnalysisState` as `{status, reason, detail}`.
fn analysis_state_json(state: &AnalysisState) -> impl nojson::DisplayJson + '_ {
    nojson::object(move |o| {
        o.member("status", state.status.as_str())?;
        match state.reason {
            Some(r) => o.member("reason", r.as_str())?,
            None => o.member("reason", &JsonNull)?,
        };
        match &state.detail {
            Some(d) => o.member("detail", d.as_str())?,
            None => o.member("detail", &JsonNull)?,
        };
        Ok(())
    })
}

fn format_json_internal(
    profile: &CapabilityProfile,
    hint: Option<&crate::legislator::project_hints::ProjectHint>,
    source_tools: Option<&[ToolCapability]>,
) -> String {
    nojson::object(|f| {
        f.member("risk_score", U32Literal(profile.risk_score))?;
        f.member("risk_level", risk_level(profile.risk_score))?;

        // target + analysis state
        let t = &profile.analysis.target;
        f.member(
            "target",
            nojson::object(|o| {
                o.member("format", t.format.as_str())?;
                o.member("isa", t.isa.as_str())?;
                o.member("abi", t.abi.as_str())?;
                o.member("endianness", t.endianness.as_str())?;
                match t.elf_class {
                    Some(c) => o.member("elf_class", c.as_str())?,
                    None => o.member("elf_class", &JsonNull)?,
                };
                match t.machine {
                    Some(m) => o.member("machine", NumLiteral(u64::from(m)))?,
                    None => o.member("machine", &JsonNull)?,
                };
                match &t.slice {
                    Some(s) => o.member("slice", s.as_str())?,
                    None => o.member("slice", &JsonNull)?,
                };
                match t.platform {
                    Some(p) => o.member("platform", p.as_str())?,
                    None => o.member("platform", &JsonNull)?,
                };
                let syscall_state = &profile.analysis.syscalls;
                o.member(
                    "slices",
                    nojson::array(|a| {
                        for s in &t.slices {
                            a.element(nojson::object(|so| {
                                so.member("arch", s.arch.as_str())?;
                                so.member("cputype", NumLiteral(u64::from(s.cputype)))?;
                                so.member("cpusubtype", NumLiteral(u64::from(s.cpusubtype)))?;
                                so.member("offset", NumLiteral(s.offset))?;
                                so.member("size", NumLiteral(s.size))?;
                                so.member("selected", BoolLiteral(s.selected))?;
                                let st = if s.selected {
                                    Some(syscall_state)
                                } else {
                                    s.state.as_ref()
                                };
                                match st {
                                    Some(st) => so.member("state", analysis_state_json(st)),
                                    None => so.member("state", &JsonNull),
                                }
                            }))?;
                        }
                        Ok(())
                    }),
                )?;
                o.member(
                    "code_regions",
                    nojson::array(|a| {
                        for r in &t.code_regions {
                            a.element(nojson::object(|ro| {
                                ro.member("name", r.name.as_str())?;
                                ro.member("file_offset", NumLiteral(r.file_offset))?;
                                match r.slice_offset {
                                    Some(o) => ro.member("slice_offset", NumLiteral(o))?,
                                    None => ro.member("slice_offset", &JsonNull)?,
                                };
                                ro.member("vaddr", NumLiteral(r.vaddr))?;
                                ro.member("size", NumLiteral(r.size))?;
                                ro.member("analyzed", BoolLiteral(r.analyzed))
                            }))?;
                        }
                        Ok(())
                    }),
                )
            }),
        )?;
        f.member(
            "analysis",
            nojson::object(|o| {
                o.member("symbols", analysis_state_json(&profile.analysis.symbols))?;
                o.member("strings", analysis_state_json(&profile.analysis.strings))?;
                o.member("syscalls", analysis_state_json(&profile.analysis.syscalls))
            }),
        )?;

        // libraries
        f.member(
            "libraries",
            nojson::array(|a| {
                for lib in &profile.symbols.libraries {
                    a.element(lib.as_str())?;
                }
                Ok(())
            }),
        )?;

        // imports
        f.member(
            "imports",
            nojson::array(|a| {
                for imp in &profile.symbols.imports {
                    a.element(nojson::object(|o| {
                        o.member("name", imp.name.as_str())?;
                        match &imp.library {
                            Some(lib) => o.member("library", lib.as_str())?,
                            None => o.member("library", &JsonNull)?,
                        };
                        let cat = match imp.category {
                            RiskCategory::Network => "network",
                            RiskCategory::FileSystem => "file_system",
                            RiskCategory::Process => "process",
                            RiskCategory::Crypto => "crypto",
                            RiskCategory::Memory => "memory",
                            RiskCategory::Safe => "safe",
                        };
                        o.member("category", cat)
                    }))?;
                }
                Ok(())
            }),
        )?;

        // risk_flags
        f.member(
            "risk_flags",
            nojson::object(|o| {
                o.member("network", BoolLiteral(profile.symbols.risk_flags.network))?;
                o.member(
                    "file_system",
                    BoolLiteral(profile.symbols.risk_flags.file_system),
                )?;
                o.member("process", BoolLiteral(profile.symbols.risk_flags.process))?;
                o.member("crypto", BoolLiteral(profile.symbols.risk_flags.crypto))?;
                o.member("memory", BoolLiteral(profile.symbols.risk_flags.memory))
            }),
        )?;

        f.member("is_stripped", BoolLiteral(profile.symbols.is_stripped))?;

        // syscalls
        f.member(
            "syscalls",
            nojson::array(|a| {
                for sc in &profile.syscalls {
                    a.element(nojson::object(|o| {
                        o.member("address", NumLiteral(sc.site.address))?;
                        match sc.syscall_number {
                            Some(n) => o.member("syscall_number", INumLiteral(n))?,
                            None => o.member("syscall_number", &JsonNull)?,
                        };
                        match &sc.syscall_name {
                            Some(n) => o.member("syscall_name", n.as_str())?,
                            None => o.member("syscall_name", &JsonNull)?,
                        };
                        o.member("kind", sc.kind.as_str())?;
                        let res = match sc.resolution {
                            Resolution::Resolved => "resolved",
                            Resolution::Unresolved => "unresolved",
                            Resolution::Ambiguous => "ambiguous",
                        };
                        o.member("resolution", res)?;
                        match sc.resolution_detail {
                            Some(d) => o.member("resolution_detail", d)?,
                            None => o.member("resolution_detail", &JsonNull)?,
                        };
                        Ok(())
                    }))?;
                }
                Ok(())
            }),
        )?;

        // strings
        f.member(
            "strings",
            nojson::object(|o| {
                o.member(
                    "urls",
                    nojson::array(|a| {
                        for u in &profile.strings.urls {
                            a.element(u.as_str())?;
                        }
                        Ok(())
                    }),
                )?;
                o.member(
                    "paths",
                    nojson::array(|a| {
                        for p in &profile.strings.paths {
                            a.element(p.as_str())?;
                        }
                        Ok(())
                    }),
                )?;
                o.member(
                    "env_vars",
                    nojson::array(|a| {
                        for e in &profile.strings.env_vars {
                            a.element(e.as_str())?;
                        }
                        Ok(())
                    }),
                )
            }),
        )?;

        // risk_summary
        f.member(
            "risk_summary",
            nojson::array(|a| {
                for line in &profile.risk_summary {
                    a.element(line.as_str())?;
                }
                Ok(())
            }),
        )?;

        // project_hints (if present)
        if let Some(h) = hint {
            f.member(
                "project_hints",
                nojson::object(|ph| {
                    ph.member("project_type", h.project_type.to_string().as_str())?;
                    ph.member("confidence_summary", h.confidence_summary.as_str())?;
                    ph.member(
                        "entry_points",
                        nojson::array(|a| {
                            for ep in &h.entry_points {
                                a.element(ep.as_str())?;
                            }
                            Ok(())
                        }),
                    )?;
                    ph.member(
                        "detected_permissions",
                        nojson::array(|a| {
                            for p in &h.detected_permissions {
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
                }),
            )?;
        }

        if let Some(tools) = source_tools {
            f.member(
                "source_tools",
                nojson::array(|a| {
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
                }),
            )?;
        }

        Ok(())
    })
    .to_string()
}

/// Format a `CapabilityProfile` along with `ProjectHint` as a single valid KDL document.
pub fn format_kdl_with_project(
    profile: &CapabilityProfile,
    hint: &crate::legislator::project_hints::ProjectHint,
) -> String {
    let mut out = format_kdl(profile);
    out.push_str("\nproject_hints {\n");
    out.push_str(&format!(
        "    project_type \"{}\"\n",
        escape_kdl_string(&hint.project_type.to_string())
    ));
    out.push_str(&format!(
        "    confidence_summary \"{}\"\n",
        escape_kdl_string(hint.confidence_summary.as_str())
    ));
    if !hint.entry_points.is_empty() {
        let eps: Vec<String> = hint
            .entry_points
            .iter()
            .map(|ep| format!("\"{}\"", escape_kdl_string(ep)))
            .collect();
        out.push_str(&format!("    entry_points {}\n", eps.join(" ")));
    }
    if !hint.detected_permissions.is_empty() {
        out.push_str("    detected_permissions {\n");
        for p in &hint.detected_permissions {
            out.push_str(&format!(
                "        permission \"{}\" confidence=\"{}\" source=\"{}\" evidence=\"{}\"\n",
                escape_kdl_string(p.permission.as_str()),
                escape_kdl_string(p.confidence.as_str()),
                escape_kdl_string(&p.source.to_string()),
                escape_kdl_string(&p.evidence)
            ));
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    out
}

/// Escape a string for use inside a KDL quoted string value.
fn escape_kdl_string(s: &str) -> String {
    crate::termutil::escape_kdl_string(s)
}

/// Format a `CapabilityProfile` as KDL.
pub fn format_kdl(profile: &CapabilityProfile) -> String {
    let mut out = String::new();

    out.push_str(&format!("risk_score {}\n", profile.risk_score));
    out.push_str(&format!(
        "risk_level \"{}\"\n",
        risk_level(profile.risk_score)
    ));
    out.push_str(&format!(
        "is_stripped {}\n",
        if profile.symbols.is_stripped {
            "#true"
        } else {
            "#false"
        }
    ));

    // target + analysis state
    let t = &profile.analysis.target;
    out.push_str(&format!(
        "target format=\"{}\" isa=\"{}\" abi=\"{}\" endianness=\"{}\"",
        t.format.as_str(),
        t.isa.as_str(),
        t.abi.as_str(),
        t.endianness.as_str(),
    ));
    if let Some(c) = t.elf_class {
        out.push_str(&format!(" elf_class=\"{}\"", c.as_str()));
    }
    if let Some(m) = t.machine {
        out.push_str(&format!(" machine={m}"));
    }
    if let Some(s) = &t.slice {
        out.push_str(&format!(" slice=\"{}\"", escape_kdl_string(s)));
    }
    if let Some(p) = t.platform {
        out.push_str(&format!(" platform=\"{}\"", p.as_str()));
    }
    out.push('\n');
    for s in &t.slices {
        out.push_str(&format!(
            "slice arch=\"{}\" cputype={} cpusubtype={} offset={} size={} selected={}",
            escape_kdl_string(&s.arch),
            s.cputype,
            s.cpusubtype,
            s.offset,
            s.size,
            if s.selected { "#true" } else { "#false" },
        ));
        let st = if s.selected {
            Some(&profile.analysis.syscalls)
        } else {
            s.state.as_ref()
        };
        if let Some(st) = st {
            out.push_str(&format!(" status=\"{}\"", st.status.as_str()));
            if let Some(r) = st.reason {
                out.push_str(&format!(" reason=\"{}\"", r.as_str()));
            }
            if let Some(d) = &st.detail {
                out.push_str(&format!(" detail=\"{}\"", escape_kdl_string(d)));
            }
        }
        out.push('\n');
    }
    for r in &t.code_regions {
        out.push_str(&format!(
            "code_region name=\"{}\" file_offset={} vaddr={} size={} analyzed={}",
            escape_kdl_string(&r.name),
            r.file_offset,
            r.vaddr,
            r.size,
            if r.analyzed { "#true" } else { "#false" },
        ));
        if let Some(o) = r.slice_offset {
            out.push_str(&format!(" slice_offset={o}"));
        }
        out.push('\n');
    }
    out.push_str("analysis {\n");
    for (name, state) in [
        ("symbols", &profile.analysis.symbols),
        ("strings", &profile.analysis.strings),
        ("syscalls", &profile.analysis.syscalls),
    ] {
        out.push_str(&format!(
            "    {} status=\"{}\"",
            name,
            state.status.as_str()
        ));
        if let Some(r) = state.reason {
            out.push_str(&format!(" reason=\"{}\"", r.as_str()));
        }
        if let Some(d) = &state.detail {
            out.push_str(&format!(" detail=\"{}\"", escape_kdl_string(d)));
        }
        out.push('\n');
    }
    out.push_str("}\n");

    // libraries
    if profile.symbols.libraries.is_empty() {
        out.push_str("libraries\n");
    } else {
        let libs: Vec<String> = profile
            .symbols
            .libraries
            .iter()
            .map(|l| format!("\"{}\"", escape_kdl_string(l)))
            .collect();
        out.push_str(&format!("libraries {}\n", libs.join(" ")));
    }

    // imports
    if !profile.symbols.imports.is_empty() {
        out.push_str("imports {\n");
        for imp in &profile.symbols.imports {
            let cat = match imp.category {
                RiskCategory::Network => "network",
                RiskCategory::FileSystem => "file_system",
                RiskCategory::Process => "process",
                RiskCategory::Crypto => "crypto",
                RiskCategory::Memory => "memory",
                RiskCategory::Safe => "safe",
            };
            if let Some(lib) = &imp.library {
                out.push_str(&format!(
                    "    import \"{}\" library=\"{}\" category=\"{}\"\n",
                    escape_kdl_string(&imp.name),
                    escape_kdl_string(lib),
                    cat
                ));
            } else {
                out.push_str(&format!(
                    "    import \"{}\" category=\"{}\"\n",
                    escape_kdl_string(&imp.name),
                    cat
                ));
            }
        }
        out.push_str("}\n");
    }

    // risk_flags
    out.push_str("risk_flags {\n");
    out.push_str(&format!(
        "    network {}\n",
        if profile.symbols.risk_flags.network {
            "#true"
        } else {
            "#false"
        }
    ));
    out.push_str(&format!(
        "    file_system {}\n",
        if profile.symbols.risk_flags.file_system {
            "#true"
        } else {
            "#false"
        }
    ));
    out.push_str(&format!(
        "    process {}\n",
        if profile.symbols.risk_flags.process {
            "#true"
        } else {
            "#false"
        }
    ));
    out.push_str(&format!(
        "    crypto {}\n",
        if profile.symbols.risk_flags.crypto {
            "#true"
        } else {
            "#false"
        }
    ));
    out.push_str(&format!(
        "    memory {}\n",
        if profile.symbols.risk_flags.memory {
            "#true"
        } else {
            "#false"
        }
    ));
    out.push_str("}\n");

    // strings
    out.push_str("strings {\n");
    if profile.strings.urls.is_empty() {
        out.push_str("    urls\n");
    } else {
        let urls: Vec<String> = profile
            .strings
            .urls
            .iter()
            .map(|u| format!("\"{}\"", escape_kdl_string(u)))
            .collect();
        out.push_str(&format!("    urls {}\n", urls.join(" ")));
    }
    if profile.strings.paths.is_empty() {
        out.push_str("    paths\n");
    } else {
        let paths: Vec<String> = profile
            .strings
            .paths
            .iter()
            .map(|p| format!("\"{}\"", escape_kdl_string(p)))
            .collect();
        out.push_str(&format!("    paths {}\n", paths.join(" ")));
    }
    if profile.strings.env_vars.is_empty() {
        out.push_str("    env_vars\n");
    } else {
        let evs: Vec<String> = profile
            .strings
            .env_vars
            .iter()
            .map(|e| format!("\"{}\"", escape_kdl_string(e)))
            .collect();
        out.push_str(&format!("    env_vars {}\n", evs.join(" ")));
    }
    out.push_str("}\n");

    // risk_summary
    if profile.risk_summary.is_empty() {
        out.push_str("risk_summary\n");
    } else {
        let items: Vec<String> = profile
            .risk_summary
            .iter()
            .map(|s| format!("\"{}\"", escape_kdl_string(s)))
            .collect();
        out.push_str(&format!("risk_summary {}\n", items.join(" ")));
    }

    // syscalls
    if !profile.syscalls.is_empty() {
        out.push_str("syscalls {\n");
        for sc in &profile.syscalls {
            out.push_str(&format!("    syscall address={}", sc.site.address));
            if let Some(n) = sc.syscall_number {
                out.push_str(&format!(" syscall_number={}", n));
            }
            if let Some(name) = &sc.syscall_name {
                out.push_str(&format!(" syscall_name=\"{}\"", escape_kdl_string(name)));
            }
            out.push_str(&format!(" kind=\"{}\"", sc.kind.as_str()));
            let res = match sc.resolution {
                Resolution::Resolved => "resolved",
                Resolution::Unresolved => "unresolved",
                Resolution::Ambiguous => "ambiguous",
            };
            out.push_str(&format!(" resolution=\"{}\"", res));
            if let Some(d) = sc.resolution_detail {
                out.push_str(&format!(" resolution_detail=\"{}\"", escape_kdl_string(d)));
            }
            out.push('\n');
        }
        out.push_str("}\n");
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::profile::test_support::make_profile;
    use crate::inspector::slicer::Resolution;

    #[test]
    fn test_format_human_contains_keywords() {
        let profile = make_profile(
            vec!["libc.so.6"],
            vec![("socket", RiskCategory::Network)],
            vec![(0x1000, Some(1), Some("write"), Resolution::Resolved)],
            vec!["https://example.com"],
            vec!["/etc/passwd"],
            vec!["HOME"],
            false,
        );
        let output = format_human(&profile);

        assert!(output.contains("=== Capability Profile ==="));
        assert!(output.contains("Risk Score:"));
        assert!(output.contains("Libraries (1):"));
        assert!(output.contains("libc.so.6"));
        assert!(output.contains("Detected Syscalls (1):"));
        assert!(output.contains("write (1) [Resolved]"));
        assert!(output.contains("URLs (1):"));
        assert!(output.contains("https://example.com"));
        assert!(output.contains("Paths (1):"));
        assert!(output.contains("/etc/passwd"));
        assert!(output.contains("Env Vars (1):"));
        assert!(output.contains("HOME"));
        assert!(output.contains("Risk Summary:"));
    }

    #[test]
    fn test_format_human_empty_profile() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], false);
        let output = format_human(&profile);

        assert!(output.contains("Risk Score: 0/100 (Low)"));
        assert!(output.contains("Libraries (0):"));
        assert!(output.contains("(none)"));
        assert!(output.contains("Detected Syscalls (0):"));
        assert!(output.contains("no risk indicators detected"));
    }

    #[test]
    fn test_format_human_high_risk_marker() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(59), Some("execve"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        let output = format_human(&profile);
        assert!(output.contains("HIGH RISK"));
    }

    // ---- format_json tests ----

    #[test]
    fn test_format_json_valid() {
        let profile = make_profile(
            vec!["libc.so.6"],
            vec![("socket", RiskCategory::Network)],
            vec![(0x1000, Some(1), Some("write"), Resolution::Resolved)],
            vec!["https://example.com"],
            vec!["/etc/passwd"],
            vec!["HOME"],
            false,
        );
        let json_str = format_json(&profile);

        // Validate it's parseable JSON
        let parsed = nojson::RawJson::parse(&json_str);
        assert!(parsed.is_ok(), "JSON should be valid: {json_str}");

        // Check key fields exist
        let raw = parsed.unwrap();
        let val = raw.value();
        assert!(val.to_member("risk_score").is_ok());
        assert!(val.to_member("risk_level").is_ok());
        assert!(val.to_member("libraries").is_ok());
        assert!(val.to_member("syscalls").is_ok());
        assert!(val.to_member("strings").is_ok());
        assert!(val.to_member("risk_summary").is_ok());
    }

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
        let native = format_json(&profile);
        assert!(
            !native.contains("source_tools"),
            "native ELF JSON must omit source_tools when unused"
        );
    }

    #[test]
    fn test_format_json_empty_profile() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], false);
        let json_str = format_json(&profile);

        let parsed = nojson::RawJson::parse(&json_str);
        assert!(parsed.is_ok(), "JSON should be valid: {json_str}");
    }

    #[test]
    fn test_format_json_risk_score_value() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(59), Some("execve"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        let json_str = format_json(&profile);
        let raw = nojson::RawJson::parse(&json_str).unwrap();
        let score_str = raw
            .value()
            .to_member("risk_score")
            .unwrap()
            .required()
            .unwrap()
            .as_number_str()
            .unwrap();
        let score: u32 = score_str.parse().unwrap();
        assert_eq!(score, 30);
    }

    // ---- format_kdl tests ----

    #[test]
    fn test_format_kdl_valid() {
        let profile = make_profile(
            vec!["libc.so.6"],
            vec![("socket", RiskCategory::Network)],
            vec![(0x1000, Some(1), Some("write"), Resolution::Resolved)],
            vec!["https://example.com"],
            vec!["/etc/passwd"],
            vec!["HOME"],
            false,
        );
        let kdl_str = format_kdl(&profile);

        // Validate it's parseable KDL
        let doc: Result<kdl::KdlDocument, _> = kdl_str.parse();
        assert!(doc.is_ok(), "KDL should be valid: {kdl_str}");

        let doc = doc.unwrap();
        assert!(doc.get("risk_score").is_some());
        assert!(doc.get("risk_level").is_some());
        assert!(doc.get("libraries").is_some());
        assert!(doc.get("risk_flags").is_some());
        assert!(doc.get("strings").is_some());
        assert!(doc.get("risk_summary").is_some());
    }

    #[test]
    fn test_format_kdl_empty_profile() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], false);
        let kdl_str = format_kdl(&profile);

        let doc: Result<kdl::KdlDocument, _> = kdl_str.parse();
        assert!(doc.is_ok(), "KDL should be valid: {kdl_str}");
    }

    #[test]
    fn test_format_kdl_risk_score_value() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(59), Some("execve"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        let kdl_str = format_kdl(&profile);
        let doc: kdl::KdlDocument = kdl_str.parse().unwrap();
        let score = doc
            .get("risk_score")
            .and_then(|n| n.get(0))
            .and_then(|v| v.as_integer())
            .unwrap();
        assert_eq!(score, 30);
    }
}
