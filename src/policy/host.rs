use std::net::Ipv6Addr;

/// Normalize a policy host pattern to the hostname form used by the auditor.
///
/// URL values are reduced to the hostname. `host:port` is reduced to the host
/// only when the host is not an IPv6 literal. Bracketed IPv6 is unwrapped to
/// the same form `extract_host_from_url` returns (for example `[::1]` → `::1`).
pub(crate) fn normalize_policy_host(pattern: &str) -> String {
    analyze_policy_host(pattern).0
}

/// The normalization above plus whether the spelling carried an explicit
/// port qualifier — `host:port`, `[v6]:port`, or a URL whose authority
/// carries one. The port is dropped because the auditor's identity is the
/// host alone, but a mechanism that emits real destination rules (PSEC)
/// must know the qualifier existed: widening it to an every-port allow
/// silently is refused instead.
pub(crate) fn analyze_policy_host(pattern: &str) -> (String, bool) {
    if pattern == "*" || pattern.starts_with("*.") {
        return (pattern.to_string(), false);
    }
    if let Some((host, port_qualified)) = extract_host_and_port_from_url(pattern) {
        return (host, port_qualified);
    }
    if pattern.starts_with('[')
        && let Some(end) = pattern.find(']')
    {
        let inner = &pattern[1..end];
        if !inner.is_empty() {
            // `[v6]` carries no port; `[v6]:port` does. A non-port suffix
            // keeps the folded-inner quirk of the pre-refactor shape.
            return (
                canonicalize_url_host(inner).unwrap_or_else(|| inner.to_ascii_lowercase()),
                valid_port_suffix(&pattern[end + 1..]),
            );
        }
    }
    // A `host:port` pattern reduces to its canonicalized host — the port
    // is not part of the identity the auditor matches on.
    if let Some((host, port)) = pattern.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return (
            canonicalize_url_host(host).unwrap_or_else(|| host.to_ascii_lowercase()),
            true,
        );
    }
    (
        canonicalize_url_host(pattern).unwrap_or_else(|| pattern.to_ascii_lowercase()),
        false,
    )
}

fn percent_decode_host(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let h1 = (bytes[i + 1] as char).to_digit(16)?;
            let h2 = (bytes[i + 2] as char).to_digit(16)?;
            decoded.push(((h1 << 4) | h2) as u8);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// Extract host from a URL string (e.g. "https://example.com/path" → "example.com").
///
/// Handles any scheme (`http`, `https`, `ftp`, `ws`, `wss`, etc.) by splitting on `://`,
/// as well as protocol-relative URLs (`//example.com/path`).
/// Handles userinfo (`user:pass@host`), IPv6 (`[::1]`), and port stripping.
/// Follows WHATWG URL Standard §4.1 (strips tab/newline) and §4.3 (percent-decodes host).
pub(crate) fn extract_host_from_url(url: &str) -> Option<String> {
    extract_host_and_port_from_url(url).map(|(host, _)| host)
}

/// `extract_host_from_url` plus whether the authority carried an explicit
/// `:port` (an empty `host:` suffix counts — it is a port qualifier
/// spelling even though it defaults the port).
fn extract_host_and_port_from_url(url: &str) -> Option<(String, bool)> {
    // WHATWG URL Standard §4.1: Remove ASCII tab or newline from input
    let stripped: String = url
        .chars()
        .filter(|&c| c != '\t' && c != '\r' && c != '\n')
        .collect();

    let after_scheme = if let Some((_scheme, rest)) = stripped.split_once("://") {
        rest
    } else {
        stripped.strip_prefix("//")?
    };

    // WHATWG URL Standard: for special schemes (http, https, ftp, ws, wss),
    // '\' is treated as a path delimiter like '/'. Authority ends at first '/', '\', '?', or '#'
    let authority = after_scheme.split(['/', '\\', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }

    // Userinfo: split at last '@'
    let host_port = if let Some((_userinfo, hp)) = authority.rsplit_once('@') {
        hp
    } else {
        authority
    };

    if host_port.is_empty() || host_port.contains('\\') {
        return None;
    }

    // IPv6 host: "[...]"; anything after ']' must be a valid :port.
    // A bare ']' — or a non-bracket host carrying a second ':' — has no
    // representable network identity and is rejected rather than
    // silently trimmed.
    let (host_str, port_qualified) = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let rest = &host_port[end + 1..];
        if !rest.is_empty() && !valid_port_suffix(rest) {
            return None;
        }
        (&host_port[1..end], !rest.is_empty())
    } else {
        match host_port.split_once(':') {
            Some((host, port)) => {
                if port.contains(':') || !valid_port(port) {
                    return None;
                }
                (host, true)
            }
            None => (host_port, false),
        }
    };

    if host_str.is_empty() {
        return None;
    }

    // WHATWG URL Standard §4.3: Percent-decode the host
    let decoded = percent_decode_host(host_str)?;

    // Reject control characters, whitespace, and WHATWG-forbidden host
    // characters. ':' is structural inside a bracketed IPv6 literal.
    if decoded.chars().any(|c| {
        c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
            || (c == ':' && !host_port.starts_with('['))
    }) {
        return None;
    }

    // The canonical network identity: IPv4 in any WHATWG spelling,
    // IPv6 folded to its compressed form, ASCII DNS names lowercased.
    // Anything the grammar cannot represent is rejected — never
    // silently treated as a DNS name.
    canonicalize_url_host(&decoded).map(|host| (host, port_qualified))
}

/// `:port` after a host: empty (`host:`), or ASCII digits ≤ 65535 —
/// WHATWG rejects larger ports for special schemes.
fn valid_port(port: &str) -> bool {
    port.is_empty()
        || (port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|p| p <= 65535))
}

/// Trailing `:port` after a bracketed IPv6 literal.
fn valid_port_suffix(rest: &str) -> bool {
    rest.strip_prefix(':').is_some_and(valid_port)
}

/// WHATWG "ends in a number" precondition: the last non-empty
/// `.`-separated label is all ASCII digits or `0x`/`0X` hex. When it
/// holds, the host MUST parse as IPv4 — the URL spec never falls back
/// to DNS for those spellings — so a parse failure is a reject.
fn host_ends_in_number(host: &str) -> bool {
    let last = host
        .rsplit('.')
        .find(|part| !part.is_empty())
        .unwrap_or_default();
    if last.is_empty() {
        return false;
    }
    last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            // A bare `0x` is the WHATWG number 0 — `parse_ipv4_number`
            // accepts it, so the empty suffix still counts as numeric.
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Canonical network identity of a URL/policy host, WHATWG-aligned:
/// bracketed IPv6 folded to its compressed form (`::ffff:`-mapped
/// literals become the dotted IPv4 they actually address), every
/// WHATWG IPv4 spelling folded to dotted decimal, ASCII DNS names
/// lowercased with the trailing root dot stripped.
///
/// `None` means the host cannot be represented — empty, non-ASCII
/// (IDNA without a UTS-46 mapping path), malformed IPv6, or an
/// ends-in-number name that is not a valid IPv4 — and callers must
/// reject rather than guess.
pub(crate) fn canonicalize_url_host(host: &str) -> Option<String> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() || !trimmed.is_ascii() {
        return None;
    }
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(trimmed);
    if inner.contains(':') {
        // Anything with a ':' is IPv6 or nothing — never a DNS name.
        let v6 = inner.parse::<Ipv6Addr>().ok()?;
        return Some(
            v6.to_ipv4_mapped()
                .map(|v4| v4.to_string())
                .unwrap_or_else(|| v6.to_string()),
        );
    }
    if host_ends_in_number(inner) {
        // The WHATWG parser lives in `pathutil` so the layer-0 `file:`
        // authority check shares this spelling table.
        return crate::pathutil::parse_ipv4_whatwg(inner).map(|v4| v4.to_string());
    }
    Some(inner.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_from_url_https() {
        assert_eq!(
            extract_host_from_url("https://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_url_http() {
        assert_eq!(
            extract_host_from_url("http://example.com:8080/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_from_url_no_scheme() {
        assert_eq!(extract_host_from_url("example.com/path"), None);
    }

    #[test]
    fn test_extract_host_from_url_rejects_forbidden_decoded_chars() {
        assert_eq!(
            extract_host_from_url("https://example.com%2fevil.test/"),
            None
        );
        assert_eq!(extract_host_from_url("https://exa%5bmple.com/"), None);
        assert_eq!(extract_host_from_url("https://%3a%3a1.evil.test/"), None);
        assert_eq!(extract_host_from_url("https://user%40name.com/path"), None);
        // ':' stays valid inside a bracketed IPv6 literal.
        assert_eq!(
            extract_host_from_url("https://[::1]:8443/"),
            Some("::1".to_string())
        );
    }
}
