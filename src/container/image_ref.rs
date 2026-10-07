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
