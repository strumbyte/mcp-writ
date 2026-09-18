use std::path::Path;
use std::sync::LazyLock;

use regex_lite::Regex;

use super::heuristics::{Confidence, Permission};
use super::project_hints::{HintSource, PermissionHint, push_safe_entry_point};

/// (package_name, permission, confidence)
const NODE_KNOWLEDGE_BASE: &[(&str, Permission, Confidence)] = &[
    // Network
    ("axios", Permission::NetworkOutbound, Confidence::High),
    ("node-fetch", Permission::NetworkOutbound, Confidence::High),
    ("got", Permission::NetworkOutbound, Confidence::High),
    ("undici", Permission::NetworkOutbound, Confidence::High),
    ("ws", Permission::NetworkOutbound, Confidence::High),
    ("express", Permission::NetworkOutbound, Confidence::High),
    ("fastify", Permission::NetworkOutbound, Confidence::High),
    ("koa", Permission::NetworkOutbound, Confidence::High),
    ("hapi", Permission::NetworkOutbound, Confidence::High),
    ("superagent", Permission::NetworkOutbound, Confidence::High),
    ("request", Permission::NetworkOutbound, Confidence::High),
    ("http-proxy", Permission::NetworkOutbound, Confidence::High),
    ("socket.io", Permission::NetworkOutbound, Confidence::High),
    (
        "socket.io-client",
        Permission::NetworkOutbound,
        Confidence::High,
    ),
    (
        "graphql-request",
        Permission::NetworkOutbound,
        Confidence::High,
    ),
    (
        "isomorphic-fetch",
        Permission::NetworkOutbound,
        Confidence::High,
    ),
    (
        "node-http-proxy",
        Permission::NetworkOutbound,
        Confidence::High,
    ),
    ("needle", Permission::NetworkOutbound, Confidence::High),
    ("bent", Permission::NetworkOutbound, Confidence::High),
    ("phin", Permission::NetworkOutbound, Confidence::High),
    // File read
    ("fs-extra", Permission::FileRead, Confidence::High),
    ("glob", Permission::FileRead, Confidence::High),
    ("chokidar", Permission::FileRead, Confidence::High),
    ("fast-glob", Permission::FileRead, Confidence::High),
    ("globby", Permission::FileRead, Confidence::High),
    ("readdir-enhanced", Permission::FileRead, Confidence::High),
    ("recursive-readdir", Permission::FileRead, Confidence::High),
    ("findit", Permission::FileRead, Confidence::High),
    // File write
    ("rimraf", Permission::FileWrite, Confidence::High),
    ("mkdirp", Permission::FileWrite, Confidence::High),
    ("del", Permission::FileWrite, Confidence::High),
    ("write-file-atomic", Permission::FileWrite, Confidence::High),
    ("fs-jetpack", Permission::FileWrite, Confidence::High),
    ("cpy", Permission::FileWrite, Confidence::High),
    ("move-file", Permission::FileWrite, Confidence::High),
    // Process exec
    ("execa", Permission::ProcessExec, Confidence::High),
    ("shelljs", Permission::ProcessExec, Confidence::High),
    ("cross-spawn", Permission::ProcessExec, Confidence::High),
    ("child_process", Permission::ProcessExec, Confidence::High),
    ("spawn-wrap", Permission::ProcessExec, Confidence::High),
    ("npm-run-all", Permission::ProcessExec, Confidence::High),
    ("concurrently", Permission::ProcessExec, Confidence::High),
    ("open", Permission::ProcessExec, Confidence::Medium),
    ("opn", Permission::ProcessExec, Confidence::Medium),
    // Database
    ("pg", Permission::DatabaseAccess, Confidence::High),
    ("mysql2", Permission::DatabaseAccess, Confidence::High),
    ("mongodb", Permission::DatabaseAccess, Confidence::High),
    ("redis", Permission::DatabaseAccess, Confidence::High),
    ("prisma", Permission::DatabaseAccess, Confidence::High),
    ("sequelize", Permission::DatabaseAccess, Confidence::High),
    ("typeorm", Permission::DatabaseAccess, Confidence::High),
    ("knex", Permission::DatabaseAccess, Confidence::High),
    ("mongoose", Permission::DatabaseAccess, Confidence::High),
    ("ioredis", Permission::DatabaseAccess, Confidence::High),
    (
        "better-sqlite3",
        Permission::DatabaseAccess,
        Confidence::High,
    ),
    ("sqlite3", Permission::DatabaseAccess, Confidence::High),
];

// Node.js source patterns
static NODE_REQUIRE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"require\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex"));
static NODE_IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"import\s+.*?\s+from\s+['"]([^'"]+)['"]"#).expect("valid regex"));
static NODE_DYNAMIC_IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"import\s*\(\s*['"]([^'"]+)['"]\s*\)"#).expect("valid regex"));

pub(crate) fn analyze_node_project(
    dir: &Path,
    hints: &mut Vec<PermissionHint>,
    entry_points: &mut Vec<String>,
) {
    let pkg_path = dir.join("package.json");
    if let Ok(content) = std::fs::read_to_string(&pkg_path) {
        // Parse dependencies from package.json using nojson
        let deps = parse_node_dependencies(&content);
        for dep in &deps {
            lookup_node_knowledge_base(dep, hints);
        }

        // Detect entry point. A crafted `main` could point outside the
        // project directory — accept only safe relative paths whose
        // canonical form still resolves inside it (no symlink escapes).
        if let Some(main) = extract_json_string_field(&content, "main") {
            push_safe_entry_point(dir, &main, entry_points);
        }
    }

    // Scan entry-point sources for imports
    for ep in entry_points.iter() {
        let ep_path = dir.join(ep);
        if let Ok(source) = std::fs::read_to_string(&ep_path) {
            scan_node_source(&source, hints);
        }
    }

    // Also scan index.js / index.ts as common entry points
    for fallback in &["index.js", "index.ts", "src/index.js", "src/index.ts"] {
        let p = dir.join(fallback);
        if p.exists() && !entry_points.iter().any(|e| e == *fallback) {
            entry_points.push(fallback.to_string());
            if let Ok(source) = std::fs::read_to_string(&p) {
                scan_node_source(&source, hints);
            }
        }
    }
}

/// Parse dependencies + devDependencies from package.json content.
fn parse_node_dependencies(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let Ok(json) = nojson::RawJson::parse(content) else {
        return deps;
    };
    let val = json.value();

    for field in &["dependencies", "devDependencies"] {
        if let Some(obj_val) = val.to_member(field).ok().and_then(|m| m.optional())
            && let Ok(obj) = obj_val.to_object()
        {
            for (key, _) in obj {
                if let Ok(name) = key.as_string_str() {
                    deps.push(name.to_string());
                }
            }
        }
    }

    deps
}

/// Extract a string field from JSON content using nojson.
fn extract_json_string_field(content: &str, field: &str) -> Option<String> {
    let json = nojson::RawJson::parse(content).ok()?;
    let val = json.value();
    let member = val.to_member(field).ok()?.optional()?;
    let s = member.as_string_str().ok()?;
    Some(s.to_string())
}

fn lookup_node_knowledge_base(dep_name: &str, hints: &mut Vec<PermissionHint>) {
    for &(pkg, ref perm, conf) in NODE_KNOWLEDGE_BASE {
        if dep_name == pkg {
            hints.push(PermissionHint {
                permission: perm.clone(),
                confidence: conf,
                source: HintSource::DependencyList,
                evidence: format!("Node.js dependency: {dep_name}"),
            });
        }
    }
}

fn scan_node_source(source: &str, hints: &mut Vec<PermissionHint>) {
    for (i, line) in source.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        // Check require() calls
        for cap in NODE_REQUIRE_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                lookup_node_source_import(m.as_str(), hints, line_no);
            }
        }
        // Check import ... from '...'
        for cap in NODE_IMPORT_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                lookup_node_source_import(m.as_str(), hints, line_no);
            }
        }
        // Check dynamic import()
        for cap in NODE_DYNAMIC_IMPORT_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                lookup_node_source_import(m.as_str(), hints, line_no);
            }
        }
    }
}

fn lookup_node_source_import(
    module_name: &str,
    hints: &mut Vec<PermissionHint>,
    line_number: usize,
) {
    // Normalize: strip scoped prefix if needed, take base package name
    let base = base_package_name(module_name);

    // Also check built-in Node modules
    match base {
        "fs" | "node:fs" | "fs/promises" | "node:fs/promises" => {
            hints.push(PermissionHint {
                permission: Permission::FileRead,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Node.js import: {module_name} at line {line_number}"),
            });
        }
        "child_process" | "node:child_process" => {
            hints.push(PermissionHint {
                permission: Permission::ProcessExec,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Node.js import: {module_name} at line {line_number}"),
            });
        }
        "net" | "node:net" | "http" | "node:http" | "https" | "node:https" | "dgram"
        | "node:dgram" => {
            hints.push(PermissionHint {
                permission: Permission::NetworkOutbound,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Node.js import: {module_name} at line {line_number}"),
            });
        }
        _ => {
            // Check against knowledge base
            for &(pkg, ref perm, conf) in NODE_KNOWLEDGE_BASE {
                if base == pkg {
                    hints.push(PermissionHint {
                        permission: perm.clone(),
                        confidence: conf,
                        source: HintSource::SourceImport,
                        evidence: format!("Node.js import: {module_name} at line {line_number}"),
                    });
                    break;
                }
            }
        }
    }
}

/// Extract the base package name from a module specifier.
/// E.g. `@scope/pkg/sub` → `@scope/pkg`, `fs/promises` → `fs`.
fn base_package_name(specifier: &str) -> &str {
    if specifier.starts_with('@') {
        // Scoped package: @scope/name/sub → @scope/name
        let mut slashes = 0;
        for (i, c) in specifier.char_indices() {
            if c == '/' {
                slashes += 1;
                if slashes == 2 {
                    return &specifier[..i];
                }
            }
        }
        specifier
    } else if let Some(rest) = specifier.strip_prefix("node:") {
        // Node built-in with prefix: node:fs/promises → node:fs
        let base = rest.split('/').next().unwrap_or(rest);
        // Return slice from original specifier: "node:" + base
        &specifier[..5 + base.len()]
    } else {
        // Regular package: name/sub → name
        specifier.split('/').next().unwrap_or(specifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legislator::project_hints::{ProjectType, analyze_project};
    use std::fs;

    fn setup_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    #[test]
    fn test_parse_node_dependencies_basic() {
        let content = r#"{
            "name": "test-mcp-server",
            "dependencies": {
                "axios": "^1.6.0",
                "fs-extra": "^11.0.0",
                "execa": "^8.0.0"
            },
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }"#;
        let deps = parse_node_dependencies(content);
        assert!(deps.contains(&"axios".to_string()));
        assert!(deps.contains(&"fs-extra".to_string()));
        assert!(deps.contains(&"execa".to_string()));
        assert!(deps.contains(&"typescript".to_string()));
    }

    #[test]
    fn test_node_knowledge_base_mapping() {
        let mut hints = Vec::new();
        lookup_node_knowledge_base("axios", &mut hints);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].permission, Permission::NetworkOutbound);
        assert_eq!(hints[0].confidence, Confidence::High);
        assert_eq!(hints[0].source, HintSource::DependencyList);
    }

    #[test]
    fn test_node_package_json_correct_permissions() {
        let dir = setup_temp_dir();
        let pkg = r#"{
            "name": "my-mcp-server",
            "main": "index.js",
            "dependencies": {
                "axios": "^1.0.0",
                "pg": "^8.0.0",
                "rimraf": "^5.0.0"
            }
        }"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::write(dir.path().join("index.js"), "// empty").unwrap();

        let result = analyze_project(dir.path());
        assert_eq!(result.project_type, ProjectType::NodeJs);

        let perms: Vec<&Permission> = result
            .detected_permissions
            .iter()
            .map(|h| &h.permission)
            .collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::DatabaseAccess));
        assert!(perms.contains(&&Permission::FileWrite));
    }

    #[test]
    fn test_node_main_parent_dir_rejected() {
        let dir = setup_temp_dir();
        let pkg = r#"{"name": "x", "main": "../outside.js"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();

        let result = analyze_project(dir.path());
        assert!(!result.entry_points.contains(&"../outside.js".to_string()));
        assert!(result.entry_points.iter().all(|e| !e.contains("..")));
    }

    #[test]
    fn test_node_main_absolute_rejected() {
        let dir = setup_temp_dir();
        let pkg = r#"{"name": "x", "main": "/etc/passwd"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();

        let result = analyze_project(dir.path());
        assert!(!result.entry_points.contains(&"/etc/passwd".to_string()));
    }

    #[test]
    fn test_node_main_missing_file_not_listed() {
        let dir = setup_temp_dir();
        let pkg = r#"{"name": "x", "main": "dist/index.js"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();

        let result = analyze_project(dir.path());
        assert!(!result.entry_points.contains(&"dist/index.js".to_string()));
    }

    #[test]
    fn test_node_source_scan_require() {
        let mut hints = Vec::new();
        let source = r#"
const http = require('http');
const fs = require('fs');
const { exec } = require('child_process');
"#;
        scan_node_source(source, &mut hints);
        let perms: Vec<&Permission> = hints.iter().map(|h| &h.permission).collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::FileRead));
        assert!(perms.contains(&&Permission::ProcessExec));
    }

    #[test]
    fn test_node_source_scan_esm_import() {
        let mut hints = Vec::new();
        let source = r#"
import axios from 'axios';
import { readFile } from 'node:fs/promises';
"#;
        scan_node_source(source, &mut hints);
        let perms: Vec<&Permission> = hints.iter().map(|h| &h.permission).collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::FileRead));
    }

    #[test]
    fn test_base_package_name() {
        assert_eq!(base_package_name("axios"), "axios");
        assert_eq!(base_package_name("fs/promises"), "fs");
        assert_eq!(base_package_name("@scope/pkg"), "@scope/pkg");
        assert_eq!(base_package_name("@scope/pkg/sub"), "@scope/pkg");
        assert_eq!(base_package_name("node:fs"), "node:fs");
        assert_eq!(base_package_name("node:fs/promises"), "node:fs");
    }
}
