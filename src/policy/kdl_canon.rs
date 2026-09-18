use std::fmt::Write as _;

use kdl::{KdlDocument, KdlNode};
use sha2::{Digest, Sha256};

use crate::error::PolicyError;

/// Canonical KDL text: positional arguments keep source order, properties are
/// sorted by name, and child node order is preserved.
pub fn canonicalize_kdl(src: &str) -> Result<String, PolicyError> {
    let mut doc: KdlDocument = src
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;
    canonicalize_document(&mut doc);
    doc.clear_format_recursive();
    doc.autoformat();
    Ok(doc.to_string())
}

/// SHA-256 of [`canonicalize_kdl`] output (`sha256:<hex>`).
pub fn hash_canonical_kdl(src: &str) -> Result<String, PolicyError> {
    let canonical = canonicalize_kdl(src)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format_sha256_digest(digest))
}

fn format_sha256_digest(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(7 + bytes.len() * 2);
    out.push_str("sha256:");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn canonicalize_document(doc: &mut KdlDocument) {
    for node in doc.nodes_mut() {
        canonicalize_node(node);
    }
}

fn canonicalize_node(node: &mut KdlNode) {
    let mut args = Vec::new();
    let mut props = Vec::new();
    for entry in node.entries().iter().cloned() {
        if entry.name().is_some() {
            props.push(entry);
        } else {
            args.push(entry);
        }
    }
    props.sort_by(|a, b| {
        let a_name = a.name().map(|n| n.value()).unwrap_or("");
        let b_name = b.name().map(|n| n.value()).unwrap_or("");
        a_name.cmp(b_name)
    });
    args.extend(props);
    *node.entries_mut() = args;
    if let Some(children) = node.children_mut() {
        canonicalize_document(children);
    }
}

#[cfg(test)]
mod tests {
    use super::{canonicalize_kdl, hash_canonical_kdl};

    const TRAJECTORY_PROPS_A: &str = r#"
trajectory #true {
    after side_effect="read_only" deny-next="network"
}
"#;

    const TRAJECTORY_PROPS_B: &str = r#"
trajectory #true {
    after deny-next="network" side_effect="read_only"
}
"#;

    #[test]
    fn trajectory_property_order_does_not_change_canonical_output_or_hash() {
        let a = canonicalize_kdl(TRAJECTORY_PROPS_A).expect("canonicalize A");
        let b = canonicalize_kdl(TRAJECTORY_PROPS_B).expect("canonicalize B");
        assert_eq!(a, b);

        let ha = hash_canonical_kdl(TRAJECTORY_PROPS_A).expect("hash A");
        let hb = hash_canonical_kdl(TRAJECTORY_PROPS_B).expect("hash B");
        assert_eq!(ha, hb);
        assert!(ha.starts_with("sha256:"));
    }

    #[test]
    fn ordered_after_children_keep_sequence() {
        let first_then_second = r#"
trajectory #true {
    after side_effect="read_only" deny-next="network"
    after side_effect="write" deny-next="execute"
}
"#;
        let second_then_first = r#"
trajectory #true {
    after side_effect="write" deny-next="execute"
    after side_effect="read_only" deny-next="network"
}
"#;
        let a = canonicalize_kdl(first_then_second).expect("canonicalize ordered A");
        let b = canonicalize_kdl(second_then_first).expect("canonicalize ordered B");
        assert_ne!(a, b);
        assert_ne!(
            hash_canonical_kdl(first_then_second).unwrap(),
            hash_canonical_kdl(second_then_first).unwrap()
        );
    }
}
