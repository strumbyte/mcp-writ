use std::path::Path;
use std::sync::LazyLock;

use regex_lite::Regex;

use super::heuristics::{Confidence, Permission};
use super::project_hints::{HintSource, PermissionHint, push_safe_entry_point};

const PYTHON_KNOWLEDGE_BASE: &[(&str, Permission, Confidence)] = &[
    // Network
    ("requests", Permission::NetworkOutbound, Confidence::High),
    ("httpx", Permission::NetworkOutbound, Confidence::High),
    ("aiohttp", Permission::NetworkOutbound, Confidence::High),
    ("urllib3", Permission::NetworkOutbound, Confidence::High),
    ("boto3", Permission::NetworkOutbound, Confidence::High),
    ("botocore", Permission::NetworkOutbound, Confidence::High),
    ("flask", Permission::NetworkOutbound, Confidence::High),
    ("django", Permission::NetworkOutbound, Confidence::High),
    ("fastapi", Permission::NetworkOutbound, Confidence::High),
    ("tornado", Permission::NetworkOutbound, Confidence::High),
    ("twisted", Permission::NetworkOutbound, Confidence::High),
    ("grpcio", Permission::NetworkOutbound, Confidence::High),
    ("websockets", Permission::NetworkOutbound, Confidence::High),
    ("paramiko", Permission::NetworkOutbound, Confidence::High),
    ("fabric", Permission::NetworkOutbound, Confidence::High),
    ("ftplib", Permission::NetworkOutbound, Confidence::High),
    ("smtplib", Permission::NetworkOutbound, Confidence::High),
    ("socket", Permission::NetworkOutbound, Confidence::Medium),
    // File read/write
    ("watchdog", Permission::FileRead, Confidence::High),
    ("shutil", Permission::FileWrite, Confidence::High),
    ("pathlib", Permission::FileRead, Confidence::Medium),
    ("tempfile", Permission::FileWrite, Confidence::Medium),
    // Process exec
    ("subprocess", Permission::ProcessExec, Confidence::High),
    ("pexpect", Permission::ProcessExec, Confidence::High),
    ("sh", Permission::ProcessExec, Confidence::High),
    ("invoke", Permission::ProcessExec, Confidence::High),
    ("plumbum", Permission::ProcessExec, Confidence::High),
    ("fabric", Permission::ProcessExec, Confidence::High),
    // Database
    ("psycopg2", Permission::DatabaseAccess, Confidence::High),
    ("psycopg", Permission::DatabaseAccess, Confidence::High),
    ("sqlalchemy", Permission::DatabaseAccess, Confidence::High),
    ("pymongo", Permission::DatabaseAccess, Confidence::High),
    ("redis", Permission::DatabaseAccess, Confidence::High),
    (
        "mysql-connector-python",
        Permission::DatabaseAccess,
        Confidence::High,
    ),
    ("pymysql", Permission::DatabaseAccess, Confidence::High),
    ("asyncpg", Permission::DatabaseAccess, Confidence::High),
    ("databases", Permission::DatabaseAccess, Confidence::High),
    ("peewee", Permission::DatabaseAccess, Confidence::High),
    ("tortoise-orm", Permission::DatabaseAccess, Confidence::High),
    // Selenium/Playwright = network + process
    ("selenium", Permission::NetworkOutbound, Confidence::High),
    ("selenium", Permission::ProcessExec, Confidence::High),
    ("playwright", Permission::NetworkOutbound, Confidence::High),
    ("playwright", Permission::ProcessExec, Confidence::High),
];

// Python source patterns
static PY_IMPORT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^import\s+([a-zA-Z_][a-zA-Z0-9_.]*)").expect("valid regex"));
static PY_FROM_IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^from\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+import").expect("valid regex")
});

pub(crate) fn analyze_python_project(
    dir: &Path,
    hints: &mut Vec<PermissionHint>,
    entry_points: &mut Vec<String>,
) {
    // Parse pyproject.toml
    let pyproject_path = dir.join("pyproject.toml");
    if let Ok(content) = std::fs::read_to_string(&pyproject_path) {
        let deps = parse_pyproject_dependencies(&content);
        for dep in &deps {
            lookup_python_knowledge_base(dep, hints);
        }

        // Extract entry point from pyproject.toml [project.scripts].
        // Same safety rule as package.json `main`: the generated path must
        // resolve inside the project directory.
        if let Some(ep) = extract_pyproject_entry_point(&content) {
            push_safe_entry_point(dir, &ep, entry_points);
        }
    }

    // Parse requirements.txt
    let req_path = dir.join("requirements.txt");
    if let Ok(content) = std::fs::read_to_string(&req_path) {
        let deps = parse_requirements_txt(&content);
        for dep in &deps {
            lookup_python_knowledge_base(dep, hints);
        }
    }

    // Scan entry-point sources
    for ep in entry_points.iter() {
        let ep_path = dir.join(ep);
        if let Ok(source) = std::fs::read_to_string(&ep_path) {
            scan_python_source(&source, hints);
        }
    }

    // Also scan common Python entry points
    for fallback in &[
        "main.py",
        "app.py",
        "server.py",
        "src/main.py",
        "__main__.py",
    ] {
        let p = dir.join(fallback);
        if p.exists() && !entry_points.iter().any(|e| e == *fallback) {
            entry_points.push(fallback.to_string());
            if let Ok(source) = std::fs::read_to_string(&p) {
                scan_python_source(&source, hints);
            }
        }
    }
}

/// Parse dependencies from pyproject.toml using shiguredo_toml.
fn parse_pyproject_dependencies(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    let Ok(table) = shiguredo_toml::from_str(content) else {
        return deps;
    };

    // [project.dependencies] - PEP 631 format
    if let Some(project) = table.get("project").and_then(|v| v.as_table()) {
        if let Some(dep_array) = project.get("dependencies").and_then(|v| v.as_array()) {
            for item in dep_array.iter() {
                if let Some(s) = item.as_str()
                    && let Some(name) = extract_python_package_name(s)
                {
                    deps.push(name);
                }
            }
        }

        // [project.optional-dependencies]
        if let Some(opt_deps) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for val in opt_deps.values() {
                if let Some(arr) = val.as_array() {
                    for item in arr.iter() {
                        if let Some(s) = item.as_str()
                            && let Some(name) = extract_python_package_name(s)
                        {
                            deps.push(name);
                        }
                    }
                }
            }
        }
    }

    // [tool.poetry.dependencies] (Poetry format)
    if let Some(tool) = table.get("tool").and_then(|v| v.as_table())
        && let Some(poetry) = tool.get("poetry").and_then(|v| v.as_table())
        && let Some(poetry_deps) = poetry.get("dependencies").and_then(|v| v.as_table())
    {
        for key in poetry_deps.keys() {
            if key != "python" {
                deps.push(key.to_string());
            }
        }
    }

    deps
}

/// Parse a requirements.txt file into package names.
pub fn parse_requirements_txt(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip empty lines, comments, and option lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if let Some(name) = extract_python_package_name(trimmed) {
            deps.push(name);
        }
    }
    deps
}

/// Extract package name from a PEP 508 dependency specifier.
/// E.g. "requests>=2.28.0" → "requests", "boto3[s3]~=1.26" → "boto3"
fn extract_python_package_name(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    // Find first char that isn't part of the package name
    let end = spec
        .find(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.')
        .unwrap_or(spec.len());
    let name = &spec[..end];
    if name.is_empty() {
        None
    } else {
        // Normalize: PEP 503 says - and _ are equivalent, lowercase
        Some(name.to_lowercase().replace('-', "_"))
    }
}

/// Extract entry point module path from pyproject.toml scripts section.
fn extract_pyproject_entry_point(content: &str) -> Option<String> {
    let table = shiguredo_toml::from_str(content).ok()?;
    let scripts = table.get("project")?.get("scripts")?.as_table()?;

    // Take the first script entry: "name = module:func"
    for val in scripts.values() {
        if let Some(s) = val.as_str() {
            // "mypackage.cli:main" → "mypackage/cli.py"
            if let Some(module_part) = s.split(':').next() {
                let path = module_part.replace('.', "/") + ".py";
                return Some(path);
            }
        }
    }
    None
}

fn lookup_python_knowledge_base(dep_name: &str, hints: &mut Vec<PermissionHint>) {
    // Normalize the dep name for comparison
    let normalized = dep_name.to_lowercase().replace('-', "_");
    for &(pkg, ref perm, conf) in PYTHON_KNOWLEDGE_BASE {
        let pkg_normalized = pkg.to_lowercase().replace('-', "_");
        if normalized == pkg_normalized {
            hints.push(PermissionHint {
                permission: perm.clone(),
                confidence: conf,
                source: HintSource::DependencyList,
                evidence: format!("Python dependency: {dep_name}"),
            });
        }
    }
}

fn scan_python_source(source: &str, hints: &mut Vec<PermissionHint>) {
    for (i, line) in source.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check `import X`
        for cap in PY_IMPORT_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                lookup_python_source_import(m.as_str(), hints, line_no);
            }
        }

        // Check `from X import ...`
        for cap in PY_FROM_IMPORT_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                lookup_python_source_import(m.as_str(), hints, line_no);
            }
        }

        // Check for dangerous patterns (sanitized: no raw source in evidence)
        if trimmed.contains("os.system(") || trimmed.contains("os.popen(") {
            hints.push(PermissionHint {
                permission: Permission::ProcessExec,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!(
                    "Python dangerous call (os.system/os.popen) at line {}",
                    line_no
                ),
            });
        }
        if trimmed.contains("os.exec") {
            hints.push(PermissionHint {
                permission: Permission::ProcessExec,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Python os.exec* call at line {}", line_no),
            });
        }
    }
}

fn lookup_python_source_import(
    module_name: &str,
    hints: &mut Vec<PermissionHint>,
    line_number: usize,
) {
    // Take the top-level module name
    let base = module_name.split('.').next().unwrap_or(module_name);
    let normalized = base.to_lowercase().replace('-', "_");

    // Check built-in dangerous modules
    match normalized.as_str() {
        "os" => {
            hints.push(PermissionHint {
                permission: Permission::FileRead,
                confidence: Confidence::Medium,
                source: HintSource::SourceImport,
                evidence: format!("Python import: {module_name} at line {line_number}"),
            });
        }
        "subprocess" => {
            hints.push(PermissionHint {
                permission: Permission::ProcessExec,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Python import: {module_name} at line {line_number}"),
            });
        }
        "socket" | "http" | "urllib" => {
            hints.push(PermissionHint {
                permission: Permission::NetworkOutbound,
                confidence: Confidence::High,
                source: HintSource::SourceImport,
                evidence: format!("Python import: {module_name} at line {line_number}"),
            });
        }
        _ => {
            // Check against knowledge base
            for &(pkg, ref perm, conf) in PYTHON_KNOWLEDGE_BASE {
                let pkg_normalized = pkg.to_lowercase().replace('-', "_");
                if normalized == pkg_normalized {
                    hints.push(PermissionHint {
                        permission: perm.clone(),
                        confidence: conf,
                        source: HintSource::SourceImport,
                        evidence: format!("Python import: {module_name} at line {line_number}"),
                    });
                }
            }
        }
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
    fn test_parse_requirements_txt_basic() {
        let content = "# Comment\nrequests>=2.28.0\nboto3~=1.26\n\n-r other.txt\nhttpx[http2]\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps, vec!["requests", "boto3", "httpx"]);
    }

    #[test]
    fn test_parse_requirements_txt_comments_ignored() {
        let content = "# This is a comment\n# requests\nflask>=2.0\n";
        let deps = parse_requirements_txt(content);
        assert_eq!(deps, vec!["flask"]);
    }

    #[test]
    fn test_parse_pyproject_pep631() {
        let content = r#"
[project]
name = "my-server"
dependencies = [
    "requests>=2.28",
    "psycopg2-binary>=2.9",
]

[project.optional-dependencies]
dev = ["pytest"]
"#;
        let deps = parse_pyproject_dependencies(content);
        assert!(deps.contains(&"requests".to_string()));
        assert!(deps.contains(&"psycopg2_binary".to_string()));
        assert!(deps.contains(&"pytest".to_string()));
    }

    #[test]
    fn test_extract_pyproject_entry_point() {
        let content = r#"
[project]
name = "my-server"

[project.scripts]
my-server = "mypackage.cli:main"
"#;
        assert_eq!(
            extract_pyproject_entry_point(content),
            Some("mypackage/cli.py".to_string())
        );
    }

    #[test]
    fn test_pyproject_scripts_entry_point_accepted() {
        let dir = setup_temp_dir();
        let content = r#"
[project]
name = "x"

[project.scripts]
x = "mypackage.cli:main"
"#;
        fs::write(dir.path().join("pyproject.toml"), content).unwrap();
        fs::create_dir_all(dir.path().join("mypackage")).unwrap();
        fs::write(dir.path().join("mypackage/cli.py"), "import os\n").unwrap();

        let result = analyze_project(dir.path());
        assert!(
            result
                .entry_points
                .contains(&"mypackage/cli.py".to_string())
        );
    }

    #[test]
    fn test_pyproject_scripts_traversal_rejected() {
        let dir = setup_temp_dir();
        let content = r#"
[project]
name = "x"

[project.scripts]
x = "../evil:main"
"#;
        fs::write(dir.path().join("pyproject.toml"), content).unwrap();

        let result = analyze_project(dir.path());
        assert!(result.entry_points.iter().all(|e| !e.contains("..")));
    }

    #[test]
    fn test_pyproject_scripts_absolute_rejected() {
        let dir = setup_temp_dir();
        let content = r#"
[project]
name = "x"

[project.scripts]
x = "/abs:main"
"#;
        fs::write(dir.path().join("pyproject.toml"), content).unwrap();

        let result = analyze_project(dir.path());
        assert!(!result.entry_points.contains(&"/abs.py".to_string()));
    }

    #[test]
    fn test_pyproject_scripts_missing_module_not_listed() {
        let dir = setup_temp_dir();
        let content = r#"
[project]
name = "x"

[project.scripts]
x = "mypackage.cli:main"
"#;
        fs::write(dir.path().join("pyproject.toml"), content).unwrap();

        let result = analyze_project(dir.path());
        assert!(
            !result
                .entry_points
                .contains(&"mypackage/cli.py".to_string())
        );
    }

    #[test]
    fn test_parse_pyproject_poetry() {
        let content = r#"
[tool.poetry.dependencies]
python = "^3.10"
httpx = "^0.24"
sqlalchemy = "^2.0"
"#;
        let deps = parse_pyproject_dependencies(content);
        assert!(deps.contains(&"httpx".to_string()));
        assert!(deps.contains(&"sqlalchemy".to_string()));
        assert!(!deps.contains(&"python".to_string()));
    }

    #[test]
    fn test_python_knowledge_base_mapping() {
        let mut hints = Vec::new();
        lookup_python_knowledge_base("requests", &mut hints);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].permission, Permission::NetworkOutbound);
    }

    #[test]
    fn test_python_requirements_correct_permissions() {
        let dir = setup_temp_dir();
        let req = "requests>=2.28\nsubprocess32\npsycopg2>=2.9\n";
        fs::write(dir.path().join("requirements.txt"), req).unwrap();

        let result = analyze_project(dir.path());
        assert_eq!(result.project_type, ProjectType::Python);

        let perms: Vec<&Permission> = result
            .detected_permissions
            .iter()
            .map(|h| &h.permission)
            .collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::DatabaseAccess));
    }

    #[test]
    fn test_python_source_scan() {
        let mut hints = Vec::new();
        let source = "import subprocess\nfrom os import system\nimport requests\n";
        scan_python_source(source, &mut hints);
        let perms: Vec<&Permission> = hints.iter().map(|h| &h.permission).collect();
        assert!(perms.contains(&&Permission::ProcessExec));
        assert!(perms.contains(&&Permission::NetworkOutbound));
    }

    #[test]
    fn test_extract_python_package_name() {
        assert_eq!(
            extract_python_package_name("requests>=2.28.0"),
            Some("requests".to_string())
        );
        assert_eq!(
            extract_python_package_name("boto3[s3]~=1.26"),
            Some("boto3".to_string())
        );
        assert_eq!(
            extract_python_package_name("psycopg2-binary"),
            Some("psycopg2_binary".to_string())
        );
        assert_eq!(extract_python_package_name(""), None);
        assert_eq!(
            extract_python_package_name("Flask==2.0.0"),
            Some("flask".to_string())
        );
    }
}
