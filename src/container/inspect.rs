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
    /// Image-declared OS version (`OsVersion` on Windows images, e.g.
    /// `10.0.26100.33438`) — the Hyper-V backend's guest-build
    /// compatibility gate reads it; absent on Linux images and on
    /// engines that do not report it.
    pub os_version: Option<String>,
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

    // Apple's `container image inspect` nests the OCI image config under
    // `[0].variants[].config.config` — a different shape from the
    // docker/podman/buildah record. Try it first; a record without a
    // `variants` member falls through to the engine-style parse.
    if let Some(meta) = parse_apple_inspect(&json)? {
        return Ok(meta);
    }

    let entrypoint = extract_config_array(&json, "Entrypoint")?;
    let cmd = extract_config_array(&json, "Cmd")?;
    let digest = extract_image_digest(&json, image);
    let env = extract_config_array(&json, "Env")?.unwrap_or_default();
    let (os, architecture, os_version) = extract_image_os_arch(&json);

    Ok(ImageMetadata {
        entrypoint,
        cmd,
        digest,
        os,
        architecture,
        os_version,
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

/// Image OS/architecture/OS-version: Docker/Podman keep them top-level
/// on the inspect object (`Os`, `Architecture`, `OsVersion`); Buildah
/// nests them under `.Docker` (docker-flavored manifest) or `.OCIv1`
/// (OCI config, lowercase keys — `os.version`).
fn extract_image_os_arch(
    json: &nojson::RawJson<'_>,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(root) = inspect_root(json) else {
        return (None, None, None);
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
    // `OsVersion` is a Windows-only image field — the Hyper-V guest
    // build it records is what `hyperv` checks against the host build.
    let os_version =
        member_string(&root, "OsVersion").or_else(|| nested("OsVersion", "os.version"));
    (os, arch, os_version)
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

    config_field_array(&config, field)
}

/// One PascalCase-or-lowercase string-array field inside an OCI image
/// config object — an absent member and JSON-null both read as "not
/// set" (the images this inspects routinely null `Cmd`).
fn config_field_array(
    config: &nojson::RawJsonValue<'_, '_>,
    field: &str,
) -> Result<Option<Vec<String>>, ContainerError> {
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

/// Apple `container image inspect` shape: the record carries
/// `variants[]` — each variant's `config` is the OCI image config
/// (`os`/`architecture` plus a nested `config` holding the
/// container-level `Entrypoint`/`Cmd`/`Env`), `platform` mirrors the
/// descriptor's selection hint, and the image's own descriptor digest
/// sits at `configuration.descriptor.digest`.
///
/// The host-architecture Linux variant is selected — the variant
/// `container run --platform linux/<host-arch>` boots. With no
/// host-arch match the first Linux variant is reported instead, so a
/// foreign-arch image fails downstream on its real architecture; with
/// no Linux variant at all the first variant is reported.
///
/// `Ok(None)` when the record has no `variants` member at all — that is
/// the docker/podman/buildah shape, left to the caller's normal path.
fn parse_apple_inspect(
    json: &nojson::RawJson<'_>,
) -> Result<Option<ImageMetadata>, ContainerError> {
    let Some(root) = inspect_root(json) else {
        return Ok(None);
    };
    let Some(variants_val) = root.to_member("variants").ok().and_then(|m| m.optional()) else {
        return Ok(None);
    };
    // A JSON-null `variants` is not the Apple shape either.
    if variants_val.kind().is_null() {
        return Ok(None);
    }
    let variants: Vec<_> = variants_val
        .to_array()
        .map_err(|e| ContainerError::InspectParse(format!("variants: {e}")))?
        .collect();
    if variants.is_empty() {
        return Err(ContainerError::InspectParse(
            "`container image inspect` record lists no image variants".to_string(),
        ));
    }

    let host = crate::execution::TargetArch::host();
    let host_arch = host.oci_name();
    let selected = variants
        .iter()
        .find(|v| {
            apple_variant_field(v, "architecture").as_deref() == Some(host_arch)
                && apple_variant_field(v, "os").as_deref() == Some("linux")
        })
        .or_else(|| {
            variants
                .iter()
                .find(|v| apple_variant_field(v, "os").as_deref() == Some("linux"))
        })
        .unwrap_or(&variants[0]);

    // Container-level fields nest under the variant's `config.config`.
    let inner_cfg = apple_variant_config(selected)
        .and_then(|c| c.to_member("config").ok().and_then(|m| m.optional()));
    let str_array = |field: &str| -> Result<Option<Vec<String>>, ContainerError> {
        match &inner_cfg {
            Some(cfg) => config_field_array(cfg, field),
            None => Ok(None),
        }
    };
    let entrypoint = str_array("Entrypoint")?;
    let cmd = str_array("Cmd")?;
    let env = str_array("Env")?.unwrap_or_default();
    let digest = root
        .to_member("configuration")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|c| c.to_member("descriptor").ok().and_then(|m| m.optional()))
        .and_then(|d| member_string(&d, "digest"));

    Ok(Some(ImageMetadata {
        entrypoint,
        cmd,
        digest,
        os: apple_variant_field(selected, "os"),
        architecture: apple_variant_field(selected, "architecture"),
        // The Apple substrate runs Linux guests only — `os.version` is a
        // Windows-image field the apple path never carries.
        os_version: None,
        env,
    }))
}

/// A variant's `config` member — the OCI image config object
/// (`os`, `architecture`, nested `config`).
fn apple_variant_config<'a>(
    v: &nojson::RawJsonValue<'a, 'a>,
) -> Option<nojson::RawJsonValue<'a, 'a>> {
    v.to_member("config").ok().and_then(|m| m.optional())
}

/// One string field on a variant: the OCI image config's own value is
/// authoritative; `platform` is only the descriptor's selection-hint
/// fallback.
fn apple_variant_field(v: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    apple_variant_config(v)
        .and_then(|c| member_string(&c, name))
        .or_else(|| {
            v.to_member("platform")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|p| member_string(&p, name))
        })
}

fn extract_image_digest(json: &nojson::RawJson<'_>, image: &str) -> Option<String> {
    let root = inspect_root(json)?;
    if let Some(digests) = root
        .to_member("RepoDigests")
        .ok()
        .and_then(|m| m.optional())
        && let Ok(arr) = digests.to_array()
    {
        let wanted = crate::workload::image_repository(image);
        for entry in arr {
            let Ok(s) = entry.to_unquoted_string_str() else {
                continue;
            };
            let owned = s.into_owned();
            let entry_repo = owned
                .rsplit_once('@')
                .map(|(repo, _)| repo)
                .unwrap_or(owned.as_str());
            if !crate::workload::repos_match(entry_repo, &wanted) {
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
            os_version: None,
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
            os_version: None,
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
            os_version: None,
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
            os_version: None,
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
            os_version: None,
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
            os_version: None,
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
        let docker_style = r#"{"Docker":{"Os":"windows","Architecture":"amd64","OsVersion":"10.0.26100.33438","config":{}},
                                "OCIv1":{"os":"windows","architecture":"amd64"}}"#;
        let meta = parse_inspect_json(docker_style, "img").unwrap();
        assert_eq!(meta.os.as_deref(), Some("windows"));
        assert_eq!(meta.architecture.as_deref(), Some("amd64"));
        assert_eq!(meta.os_version.as_deref(), Some("10.0.26100.33438"));

        let oci_style = r#"{"OCIv1":{"os":"linux","architecture":"arm64","os.version":"10.0.22000","config":{}}}"#;
        let meta = parse_inspect_json(oci_style, "img").unwrap();
        assert_eq!(meta.os.as_deref(), Some("linux"));
        assert_eq!(meta.architecture.as_deref(), Some("arm64"));
        assert_eq!(meta.os_version.as_deref(), Some("10.0.22000"));
    }

    /// `OsVersion` rides the same top-level/nested fallbacks as `Os` —
    /// the Hyper-V backend's guest-build gate reads it.
    #[test]
    fn test_os_version_docker_shape() {
        let json = r#"[{"Os":"windows","Architecture":"amd64","OsVersion":"10.0.26100.33438","Config":{}}]"#;
        let meta = parse_inspect_json(json, "img").unwrap();
        assert_eq!(meta.os.as_deref(), Some("windows"));
        assert_eq!(meta.os_version.as_deref(), Some("10.0.26100.33438"));
    }

    #[test]
    fn test_os_arch_missing_fields() {
        let json = r#"[{"Config":{"Entrypoint":[]}}]"#;
        let meta = parse_inspect_json(json, "img").unwrap();
        assert_eq!(meta.os, None);
        assert_eq!(meta.architecture, None);
        assert!(meta.env.is_empty());
    }

    // --- Apple `container image inspect` shape --------------------------
    //
    // Real record from `container image inspect` (fields abbreviated):
    // `[{configuration:{descriptor:{digest}}, variants:[{platform,
    //   config:{os,architecture,config:{Env,Entrypoint,Cmd}}}]}]`.

    fn apple_inspect_json(variants: &str) -> String {
        format!(
            r#"[{{
                "id": "d75cdd72874d",
                "configuration": {{
                    "name": "gcr.io/distroless/static-debian12",
                    "descriptor": {{
                        "digest": "sha256:d75c",
                        "mediaType": "application/vnd.oci.image.index.v1+json",
                        "size": 1514
                    }}
                }},
                "variants": {variants}
            }}]"#
        )
    }

    #[test]
    fn test_apple_shape_selects_host_arch_variant() {
        let json = apple_inspect_json(
            r#"[
            {
                "platform": {"architecture": "amd64", "os": "linux"},
                "config": {
                    "architecture": "amd64",
                    "os": "linux",
                    "config": {
                        "Env": ["PATH=/usr/bin", "MCP_WRIT_MARKER=amd64"],
                        "User": "0"
                    }
                }
            },
            {
                "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
                "config": {
                    "architecture": "arm64",
                    "os": "linux",
                    "config": {
                        "Env": ["PATH=/usr/bin", "MCP_WRIT_MARKER=arm64"],
                        "Entrypoint": ["/usr/local/bin/mcp-secure-runner"],
                        "Cmd": null,
                        "User": "0",
                        "WorkingDir": "/"
                    }
                }
            }
        ]"#,
        );
        let meta = parse_inspect_json(&json, "img@sha256:d75c").unwrap();
        // The selected variant is the one `container run --platform
        // linux/<host-arch>` boots — the host architecture, whichever
        // array position it sits at.
        let host = crate::execution::TargetArch::host();
        let host_arch = host.oci_name();
        assert_eq!(meta.architecture.as_deref(), Some(host_arch));
        assert_eq!(meta.os.as_deref(), Some("linux"));
        assert_eq!(meta.digest.as_deref(), Some("sha256:d75c"));
        assert!(
            meta.env
                .iter()
                .any(|e| e == &format!("MCP_WRIT_MARKER={host_arch}")),
            "selected variant env: {:?}",
            meta.env
        );
    }

    /// A single-variant image reports its real architecture even when it
    /// is not the host's — the downstream arch check must refuse the
    /// image it actually inspected, not a guessed host arch.
    #[test]
    fn test_apple_shape_reports_foreign_arch_truthfully() {
        let json = apple_inspect_json(
            r#"[
            {
                "platform": {"architecture": "amd64", "os": "linux"},
                "config": {
                    "architecture": "amd64",
                    "os": "linux",
                    "config": {"Env": ["PATH=/usr/bin"], "Entrypoint": ["/bin/app"]}
                }
            }
        ]"#,
        );
        let meta = parse_inspect_json(&json, "img").unwrap();
        assert_eq!(meta.architecture.as_deref(), Some("amd64"));
        assert_eq!(meta.os.as_deref(), Some("linux"));
        assert_eq!(
            meta.entrypoint,
            Some(vec!["/bin/app".to_string()]),
            "container-level fields come from config.config"
        );
        assert_eq!(meta.cmd, None);
    }

    /// Distroless-style minimal images omit `Entrypoint`/`Cmd` members
    /// entirely — absence reads as "not set", not a parse failure.
    #[test]
    fn test_apple_shape_absent_container_fields() {
        let json = apple_inspect_json(
            r#"[
            {
                "platform": {"architecture": "arm64", "os": "linux"},
                "config": {
                    "architecture": "arm64",
                    "os": "linux",
                    "config": {"Env": ["PATH=/usr/bin"], "User": "0", "WorkingDir": "/"}
                }
            }
        ]"#,
        );
        let meta = parse_inspect_json(&json, "img").unwrap();
        assert_eq!(meta.entrypoint, None);
        assert_eq!(meta.cmd, None);
        assert_eq!(meta.env.len(), 1);
    }

    #[test]
    fn test_apple_shape_empty_variants_errors() {
        let json = apple_inspect_json("[]");
        let err = parse_inspect_json(&json, "img").unwrap_err();
        match err {
            ContainerError::InspectParse(msg) => {
                assert!(msg.contains("no image variants"), "got: {msg}")
            }
            other => panic!("expected InspectParse, got: {other:?}"),
        }
    }

    /// `variants` absent or null is not the Apple shape — the record
    /// parses through the normal docker/podman path instead.
    #[test]
    fn test_apple_shape_not_claimed_by_null_variants() {
        let json = r#"[{"variants": null, "Os": "linux", "Architecture": "amd64",
                       "Config": {"Entrypoint": ["/bin/sh"]}}]"#;
        let meta = parse_inspect_json(json, "img").unwrap();
        assert_eq!(meta.entrypoint, Some(vec!["/bin/sh".to_string()]));
        assert_eq!(meta.architecture.as_deref(), Some("amd64"));
        assert_eq!(meta.digest, None);
    }
}
