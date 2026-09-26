use crate::container::engine::ContainerEngine;
use crate::error::ContainerError;

/// Metadata extracted from a container image via `docker/podman/buildah inspect`.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageMetadata {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub digest: Option<String>,
    /// Image-declared guest OS (`linux`, `windows`, …) — the workload's
    /// OS, distinct from both the CLI host and the engine's host.
    pub os: Option<String>,
    /// Image-declared CPU architecture (`amd64`, `arm64`, …).
    pub architecture: Option<String>,
    /// `Config.Env` entries (`KEY=value`), e.g. the runner capability
    /// marker recorded by `wrap-image`/`containerize`.
    pub env: Vec<String>,
}

/// Run image inspect via the ContainerEngine abstraction and parse the JSON output.
pub async fn inspect_image(
    engine: &dyn ContainerEngine,
    image: &str,
) -> Result<ImageMetadata, ContainerError> {
    let stdout = engine
        .inspect(image)
        .await
        .map_err(|e| ContainerError::InspectExec(e.to_string()))?;
    parse_inspect_json(&stdout, image)
}

/// Parse the JSON output of container image inspect and extract entrypoint/cmd.
fn parse_inspect_json(json_str: &str, image: &str) -> Result<ImageMetadata, ContainerError> {
    let json = nojson::RawJson::parse(json_str)
        .map_err(|e| ContainerError::InspectParse(format!("invalid JSON: {e}")))?;

    let entrypoint = extract_config_array(&json, "Entrypoint")?;
    let cmd = extract_config_array(&json, "Cmd")?;
    let digest = extract_image_digest(&json, image);
    let env = extract_config_array(&json, "Env")?.unwrap_or_default();
    let (os, architecture) = extract_image_os_arch(&json);

    Ok(ImageMetadata {
        entrypoint,
        cmd,
        digest,
        os,
        architecture,
        env,
    })
}

/// The single inspect root object: `[ {...} ]` (Docker/Podman) or
/// `{...}` (Buildah). `None` on an empty array.
fn inspect_root<'a>(json: &'a nojson::RawJson<'a>) -> Option<nojson::RawJsonValue<'a, 'a>> {
    if let Ok(mut arr) = json.value().to_array() {
        arr.next()
    } else {
        Some(json.value())
    }
}

/// Decode a string member of `obj`, tolerating a missing or `null` value.
fn member_string(obj: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    let v = obj.to_member(name).ok().and_then(|m| m.optional())?;
    v.to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
        .filter(|s| !s.is_empty())
}

/// Image OS/architecture: Docker/Podman keep them top-level on the
/// inspect object; Buildah nests them under `.Docker` (docker-flavored
/// manifest) or `.OCIv1` (OCI config, lowercase keys).
fn extract_image_os_arch(json: &nojson::RawJson<'_>) -> (Option<String>, Option<String>) {
    let Some(root) = inspect_root(json) else {
        return (None, None);
    };
    let docker = root.to_member("Docker").ok().and_then(|m| m.optional());
    let ociv1 = root.to_member("OCIv1").ok().and_then(|m| m.optional());
    let nested = |name: &str, lower: &str| {
        docker
            .and_then(|d| member_string(&d, name))
            .or_else(|| ociv1.and_then(|o| member_string(&o, lower)))
    };
    let os = member_string(&root, "Os").or_else(|| nested("Os", "os"));
    let arch =
        member_string(&root, "Architecture").or_else(|| nested("Architecture", "architecture"));
    (os, arch)
}

/// Navigate `[0].Config.{field}` (or Buildah's structure) and extract as `Option<Vec<String>>`.
fn extract_config_array(
    json: &nojson::RawJson<'_>,
    field: &str,
) -> Result<Option<Vec<String>>, ContainerError> {
    // Inspect output can be an array [ {...} ] (Docker/Podman) or a single object {...} (Buildah)
    let root = inspect_root(json)
        .ok_or_else(|| ContainerError::InspectParse("empty inspect array".to_string()))?;

    // Try finding Config (Docker/Podman: .Config, or Buildah: .Docker.config / .OCIv1.config / .Config)
    let config = if let Some(c) = root.to_member("Config").ok().and_then(|m| m.optional()) {
        Some(c)
    } else if let Some(docker_config) = root
        .to_member("Docker")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|d| d.to_member("config").ok().and_then(|m| m.optional()))
    {
        Some(docker_config)
    } else if let Some(o) = root.to_member("OCIv1").ok().and_then(|m| m.optional()) {
        o.to_member("config").ok().and_then(|m| m.optional())
    } else {
        None
    };

    let config = match config {
        Some(c) => c,
        None => return Ok(None),
    };

    let field_val = match config.to_member(field).ok().and_then(|m| m.optional()) {
        Some(v) => v,
        None => {
            let lower = field.to_lowercase();
            match config.to_member(&lower).ok().and_then(|m| m.optional()) {
                Some(v) => v,
                None => return Ok(None),
            }
        }
    };

    // null means "not set" in docker inspect output
    if field_val.kind().is_null() {
        return Ok(None);
    }

    // Parse as array of strings, decoding JSON escapes via to_unquoted_string_str
    let mut result = Vec::new();
    for elem in field_val
        .to_array()
        .map_err(|e| ContainerError::InspectParse(format!("{field} is not an array: {e}")))?
    {
        let s = elem.to_unquoted_string_str().map_err(|e| {
            ContainerError::InspectParse(format!("{field} element not a valid string: {e}"))
        })?;
        result.push(s.into_owned());
    }

    Ok(Some(result))
}

fn extract_image_digest(json: &nojson::RawJson<'_>, image: &str) -> Option<String> {
    let root = inspect_root(json)?;
    if let Some(digests) = root
        .to_member("RepoDigests")
        .ok()
        .and_then(|m| m.optional())
        && let Ok(arr) = digests.to_array()
    {
        let wanted = image_repository(image);
        for entry in arr {
            let Ok(s) = entry.to_unquoted_string_str() else {
                continue;
            };
            let owned = s.into_owned();
            let entry_repo = owned
                .rsplit_once('@')
                .map(|(repo, _)| repo)
                .unwrap_or(owned.as_str());
            if !repos_match(entry_repo, &wanted) {
                continue;
            }
            if let Some((_, digest)) = owned.rsplit_once('@') {
                return Some(digest.to_string());
            }
            if owned.starts_with("sha256:") {
                return Some(owned);
            }
        }
    }
    None
}

/// Repository portion of an image reference (tag and digest stripped).
fn image_repository(reference: &str) -> String {
    let mut s = reference;
    if let Some((repo, digest)) = reference.rsplit_once('@')
        && digest.starts_with("sha256:")
    {
        s = repo;
    }
    if let Some(slash) = s.rfind('/') {
        if let Some(colon) = s[slash + 1..].rfind(':') {
            return s[..slash + 1 + colon].to_string();
        }
    } else if let Some(colon) = s.rfind(':') {
        return s[..colon].to_string();
    }
    s.to_string()
}

fn repos_match(entry_repo: &str, wanted: &str) -> bool {
    if wanted.is_empty() {
        return false;
    }
    normalize_repository(entry_repo) == normalize_repository(wanted)
}

/// Canonicalize a repository by filling in Docker Hub (`docker.io`) and the
/// omitted official-image namespace (`library`) only. Other registries are
/// left unchanged so a suffix cannot match a different registry.
fn normalize_repository(repo: &str) -> String {
    let (registry, path) = match repo.split_once('/') {
        Some((first, rest)) if is_registry_host(first) => (first, rest.to_string()),
        Some(_) => ("docker.io", repo.to_string()),
        None => ("docker.io", repo.to_string()),
    };
    let path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path
    };
    format!("{registry}/{path}")
}

fn is_registry_host(first: &str) -> bool {
    first == "localhost" || first.contains('.') || first.contains(':')
}

/// Convert image metadata to JSON-encoded environment variable values.
///
/// Returns `(entrypoint_json, cmd_json)` where each is a JSON array string
/// (e.g. `["node","server.js"]`) or `"null"` if absent.
pub fn metadata_to_env_vars(meta: &ImageMetadata) -> (String, String) {
    let entrypoint_json = match &meta.entrypoint {
        Some(v) => vec_to_json_array(v),
        None => "null".to_string(),
    };
    let cmd_json = match &meta.cmd {
        Some(v) => vec_to_json_array(v),
        None => "null".to_string(),
    };
    (entrypoint_json, cmd_json)
}

/// Serialize a string slice to a JSON array string without serde.
fn vec_to_json_array(v: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\x08' => out.push_str("\\b"),
                '\x0C' => out.push_str("\\f"),
                c if c <= '\u{001F}' => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal docker inspect JSON with given entrypoint/cmd fragments.
    fn make_inspect_json(entrypoint: &str, cmd: &str) -> String {
        format!(r#"[{{"Config":{{"Entrypoint":{entrypoint},"Cmd":{cmd}}}}}]"#)
    }

    // --- parse_inspect_json tests ---

    #[test]
    fn test_both_entrypoint_and_cmd() {
        let json = make_inspect_json(r#"["/docker-entrypoint.sh"]"#, r#"["node","server.js"]"#);
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(
            meta.entrypoint,
            Some(vec!["/docker-entrypoint.sh".to_string()])
        );
        assert_eq!(
            meta.cmd,
            Some(vec!["node".to_string(), "server.js".to_string()])
        );
    }

    #[test]
    fn test_escaped_strings_in_entrypoint_and_cmd() {
        let json = make_inspect_json(
            r#"["python3","-c","print(\"hello\")"]"#,
            r#"["tool","--path","C:\\workspace\\data"]"#,
        );
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(
            meta.entrypoint,
            Some(vec![
                "python3".to_string(),
                "-c".to_string(),
                "print(\"hello\")".to_string(),
            ])
        );
        assert_eq!(
            meta.cmd,
            Some(vec![
                "tool".to_string(),
                "--path".to_string(),
                "C:\\workspace\\data".to_string(),
            ])
        );
    }

    #[test]
    fn test_entrypoint_only() {
        let json = make_inspect_json(r#"["/bin/sh","-c"]"#, "null");
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(
            meta.entrypoint,
            Some(vec!["/bin/sh".to_string(), "-c".to_string()])
        );
        assert_eq!(meta.cmd, None);
    }

    #[test]
    fn test_cmd_only() {
        let json = make_inspect_json("null", r#"["python","app.py"]"#);
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(meta.entrypoint, None);
        assert_eq!(
            meta.cmd,
            Some(vec!["python".to_string(), "app.py".to_string()])
        );
    }

    #[test]
    fn test_both_null() {
        let json = make_inspect_json("null", "null");
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(meta.entrypoint, None);
        assert_eq!(meta.cmd, None);
    }

    #[test]
    fn test_empty_arrays() {
        let json = make_inspect_json("[]", "[]");
        let meta = parse_inspect_json(&json, "").unwrap();
        assert_eq!(meta.entrypoint, Some(vec![]));
        assert_eq!(meta.cmd, Some(vec![]));
    }

    #[test]
    fn test_config_missing() {
        let json = r#"[{"Id":"sha256:abc"}]"#;
        let meta = parse_inspect_json(json, "nginx:latest").unwrap();
        assert_eq!(meta.entrypoint, None);
        assert_eq!(meta.cmd, None);
        assert_eq!(meta.digest, None);
    }

    #[test]
    fn test_repo_digest_matches_requested_image() {
        let json = r#"[{
            "RepoDigests": [
                "docker.io/library/other@sha256:aaaa",
                "ghcr.io/org/app@sha256:bbbb"
            ]
        }]"#;
        let meta = parse_inspect_json(json, "ghcr.io/org/app:v1").unwrap();
        assert_eq!(meta.digest.as_deref(), Some("sha256:bbbb"));
    }

    #[test]
    fn test_repo_digest_none_when_no_match() {
        let json = r#"[{"RepoDigests":["docker.io/library/other@sha256:aaaa"]}]"#;
        let meta = parse_inspect_json(json, "nginx:latest").unwrap();
        assert_eq!(meta.digest, None);
    }

    #[test]
    fn test_repo_digest_normalizes_docker_hub_library() {
        let json = r#"[{"RepoDigests":["docker.io/library/nginx@sha256:cccc"]}]"#;
        let meta = parse_inspect_json(json, "nginx:latest").unwrap();
        assert_eq!(meta.digest.as_deref(), Some("sha256:cccc"));
    }

    #[test]
    fn test_repo_digest_does_not_match_other_registry_suffix() {
        let json = r#"[{"RepoDigests":["ghcr.io/library/nginx@sha256:dddd"]}]"#;
        let meta = parse_inspect_json(json, "nginx:latest").unwrap();
        assert_eq!(meta.digest, None);
    }

    #[test]
    fn test_invalid_json_errors() {
        let err = parse_inspect_json("not json", "").unwrap_err();
        match err {
            ContainerError::InspectParse(msg) => assert!(msg.contains("invalid JSON")),
            other => panic!("expected InspectParse, got: {other:?}"),
        }
    }

    #[test]
    fn test_empty_array_errors() {
        let err = parse_inspect_json("[]", "").unwrap_err();
        match err {
            ContainerError::InspectParse(msg) => assert!(msg.contains("empty inspect array")),
            other => panic!("expected InspectParse, got: {other:?}"),
        }
    }

    // --- metadata_to_env_vars tests ---

    #[test]
    fn test_env_vars_both_present() {
        let meta = ImageMetadata {
            entrypoint: Some(vec!["/docker-entrypoint.sh".to_string()]),
            cmd: Some(vec!["node".to_string(), "server.js".to_string()]),
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, r#"["/docker-entrypoint.sh"]"#);
        assert_eq!(cmd, r#"["node","server.js"]"#);
    }

    #[test]
    fn test_env_vars_entrypoint_only() {
        let meta = ImageMetadata {
            entrypoint: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            cmd: None,
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, r#"["/bin/sh","-c"]"#);
        assert_eq!(cmd, "null");
    }

    #[test]
    fn test_env_vars_cmd_only() {
        let meta = ImageMetadata {
            entrypoint: None,
            cmd: Some(vec!["python".to_string(), "app.py".to_string()]),
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, "null");
        assert_eq!(cmd, r#"["python","app.py"]"#);
    }

    #[test]
    fn test_env_vars_both_none() {
        let meta = ImageMetadata {
            entrypoint: None,
            cmd: None,
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, "null");
        assert_eq!(cmd, "null");
    }

    #[test]
    fn test_env_vars_escapes_special_chars() {
        let meta = ImageMetadata {
            entrypoint: Some(vec![r#"echo "hello""#.to_string()]),
            cmd: Some(vec!["path\\to\\file".to_string()]),
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, r#"["echo \"hello\""]"#);
        assert_eq!(cmd, r#"["path\\to\\file"]"#);
    }

    #[test]
    fn test_env_vars_empty_arrays() {
        let meta = ImageMetadata {
            entrypoint: Some(vec![]),
            cmd: Some(vec![]),
            digest: None,
            os: None,
            architecture: None,
            env: Vec::new(),
        };
        let (ep, cmd) = metadata_to_env_vars(&meta);
        assert_eq!(ep, "[]");
        assert_eq!(cmd, "[]");
    }

    // --- os / architecture / env extraction ---

    #[test]
    fn test_os_arch_and_env_docker_shape() {
        let json = r#"[{
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "Entrypoint": ["/usr/local/bin/mcp-secure-runner"],
                "Env": ["PATH=/usr/bin", "MCP_WRIT_RUNNER_CAPS={\"v\":\"1.0\",\"caps\":[\"guest-report-1\"]}"]
            }
        }]"#;
        let meta = parse_inspect_json(json, "img@sha256:x").unwrap();
        assert_eq!(meta.os.as_deref(), Some("linux"));
        assert_eq!(meta.architecture.as_deref(), Some("amd64"));
        assert_eq!(meta.env.len(), 2);
        assert!(
            meta.env[1].starts_with("MCP_WRIT_RUNNER_CAPS="),
            "env: {:?}",
            meta.env
        );
    }

    #[test]
    fn test_os_arch_buildah_shapes() {
        let docker_style = r#"{"Docker":{"Os":"windows","Architecture":"amd64","config":{}},
                                "OCIv1":{"os":"windows","architecture":"amd64"}}"#;
        let meta = parse_inspect_json(docker_style, "img").unwrap();
        assert_eq!(meta.os.as_deref(), Some("windows"));
        assert_eq!(meta.architecture.as_deref(), Some("amd64"));

        let oci_style = r#"{"OCIv1":{"os":"linux","architecture":"arm64","config":{}}}"#;
        let meta = parse_inspect_json(oci_style, "img").unwrap();
        assert_eq!(meta.os.as_deref(), Some("linux"));
        assert_eq!(meta.architecture.as_deref(), Some("arm64"));
    }

    #[test]
    fn test_os_arch_missing_fields() {
        let json = r#"[{"Config":{"Entrypoint":[]}}]"#;
        let meta = parse_inspect_json(json, "img").unwrap();
        assert_eq!(meta.os, None);
        assert_eq!(meta.architecture, None);
        assert!(meta.env.is_empty());
    }
}
