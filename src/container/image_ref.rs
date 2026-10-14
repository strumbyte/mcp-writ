//! Strict validation of OCI image references before they are embedded
//! into a generated Dockerfile `FROM` line or passed to an engine CLI.
//!
//! The reference is rendered verbatim — a value containing whitespace,
//! a comment marker, or a line-continuation escape can inject extra
//! Dockerfile instructions, so the check is an allowlist rather than a
//! blocklist: the first character must be alphanumeric or `[` and every
//! subsequent character must come from the OCI grammar's character set
//! (`A-Z a-z 0-9 . _ - / : @ [ ]` — `[`/`]` cover IPv6-literal
//! registries). Anything else is refused outright.

/// Longest accepted image reference (well past real-world names).
pub const MAX_IMAGE_REF_LEN: usize = 512;

/// Validate `image` as a Dockerfile-safe OCI image reference.
///
/// This deliberately does not try to *parse* the reference (registry /
/// repository / tag / digest grammar is the engine's job); it proves the
/// string is a single safe token — no whitespace, comments, escapes, or
/// shell/Dockerfile metacharacters.
pub fn validate_image_reference(image: &str) -> Result<(), String> {
    if image.is_empty() {
        return Err("image reference must not be empty".to_string());
    }
    if image.len() > MAX_IMAGE_REF_LEN {
        return Err(format!("image reference exceeds {MAX_IMAGE_REF_LEN} bytes"));
    }
    let mut chars = image.chars();
    let first = chars.next().expect("non-empty");
    // `[` opens an IPv6-literal registry (`[fd00::1]:5000/ns/img`); it
    // is still a plain Dockerfile token with no instruction meaning.
    if !(first.is_ascii_alphanumeric() || first == '[') {
        return Err(format!(
            "image reference must start with an alphanumeric character or '[', got '{first}'"
        ));
    }
    if let Some(bad) = chars.find(|c| !is_image_ref_char(*c)) {
        return Err(format!(
            "image reference contains disallowed character '{bad}'"
        ));
    }
    Ok(())
}

fn is_image_ref_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' | '/' | ':' | '@' | '[' | ']')
}

/// True for a well-formed `sha256:` digest — 64 hex digits after the
/// algorithm prefix. Engine-supplied digest/id strings are embedded
/// into the launch/build reference, so a malformed value is rejected
/// rather than interpolated.
pub(crate) fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].chars().all(|c| c.is_ascii_hexdigit())
}

/// The immutable reference a launch or generated `FROM` binds to:
/// `repo@<digest>` built from the inspected repo digest, an
/// already-pinned reference, or the engine-provided image id. A tag
/// only *names* the inspected object at inspect time — it can
/// re-resolve to different bytes before the engine consumes it, so the
/// mutable spelling never reaches the launch or the Dockerfile.
pub(crate) fn immutable_image_ref(
    reference: &str,
    meta: &crate::container::inspect::ImageMetadata,
) -> Option<String> {
    if let Some(digest) = meta.digest.as_deref().filter(|d| is_sha256_digest(d)) {
        let repo = crate::workload::image_repository(reference);
        if !repo.is_empty() {
            return Some(format!("{repo}@{digest}"));
        }
    }
    if crate::container::runner::image_ref_is_digest_pinned(reference) {
        return Some(reference.to_string());
    }
    meta.image_id
        .as_deref()
        .filter(|id| {
            is_sha256_digest(id) || (id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_references() {
        for image in [
            "node:20-slim",
            "python:3.12",
            "ubuntu:24.04",
            "mcr.microsoft.com/windows/servercore@sha256:abc123",
            "registry.internal:5000/ns/img:v1.2.3",
            "img@sha256:deadbeef",
            "localhost:5000/test",
            "[fd00::1]:5000/ns/img",
            "a",
            "img__name",
        ] {
            assert!(validate_image_reference(image).is_ok(), "{image}");
        }
    }

    #[test]
    fn rejects_dockerfile_injection() {
        for image in [
            "node:20\nRUN evil",
            "node:20\r\nRUN evil",
            "node:20 \\\n RUN evil",
            "img # comment",
            "img\tevil",
            "img name",
            "img$(id)",
            "img`id`",
            "img;rm",
            "img|sh",
            "img&x",
            "img>f",
            "img<f",
            "img\"x",
            "img'x",
            "img*",
            "img?x",
            "img!x",
            "img,x",
            "img=x",
            "img(x)",
            "img{x}",
            "img\x01",
        ] {
            assert!(
                validate_image_reference(image).is_err(),
                "must reject: {image:?}"
            );
        }
    }

    /// The digest reported by inspect rewrites a tag ref into
    /// `repo@sha256:…` — the mutable spelling never reaches `FROM`/`run`.
    #[test]
    fn immutable_ref_binds_inspected_digest() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let meta = crate::container::inspect::ImageMetadata {
            entrypoint: None,
            cmd: None,
            digest: Some(digest.clone()),
            image_id: Some(format!("sha256:{}", "cd".repeat(32))),
            os: None,
            architecture: None,
            os_version: None,
            env: Vec::new(),
        };
        assert_eq!(
            immutable_image_ref("ghcr.io/org/app:v1", &meta).as_deref(),
            Some(format!("ghcr.io/org/app@{digest}").as_str())
        );
    }

    /// A digest-pinned reference stands on its own; a bare image id is
    /// the fallback for a digest-less store entry; neither missing means
    /// no immutable binding exists.
    #[test]
    fn immutable_ref_fallbacks() {
        let empty = crate::container::inspect::ImageMetadata {
            entrypoint: None,
            cmd: None,
            digest: None,
            image_id: None,
            os: None,
            architecture: None,
            os_version: None,
            env: Vec::new(),
        };
        let pinned = format!("img@sha256:{}", "ef".repeat(32));
        assert_eq!(
            immutable_image_ref(&pinned, &empty).as_deref(),
            Some(pinned.as_str())
        );
        assert_eq!(immutable_image_ref("img:latest", &empty), None);

        // A bare 64-hex image id binds as the engine reference.
        let meta = crate::container::inspect::ImageMetadata {
            image_id: Some("cd".repeat(32)),
            ..empty.clone()
        };
        assert_eq!(
            immutable_image_ref("img:latest", &meta).as_deref(),
            Some("cd".repeat(32).as_str())
        );
        // Malformed/short ids are never interpolated into a reference.
        let bad = crate::container::inspect::ImageMetadata {
            image_id: Some("not-a-digest".to_string()),
            ..empty
        };
        assert_eq!(immutable_image_ref("img:latest", &bad), None);
    }

    #[test]
    fn sha256_digest_shape() {
        assert!(is_sha256_digest(&format!("sha256:{}", "ab".repeat(32))));
        assert!(!is_sha256_digest("sha256:short"));
        assert!(!is_sha256_digest(&format!("md5:{}", "ab".repeat(32))));
    }

    #[test]
    fn rejects_edge_shapes() {
        assert!(validate_image_reference("").is_err());
        assert!(validate_image_reference("-img").is_err());
        assert!(validate_image_reference(".img").is_err());
        assert!(validate_image_reference("/img").is_err());
        assert!(validate_image_reference(":img").is_err());
        assert!(validate_image_reference("@img").is_err());
        assert!(validate_image_reference(&"i".repeat(MAX_IMAGE_REF_LEN + 1)).is_err());
        assert!(validate_image_reference(&"i".repeat(MAX_IMAGE_REF_LEN)).is_ok());
    }
}
