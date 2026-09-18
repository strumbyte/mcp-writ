/// Normalize a policy host pattern to the hostname form used by the auditor.
///
/// URL values are reduced to the hostname. `host:port` is reduced to the host
/// only when the host is not an IPv6 literal. Bracketed IPv6 is unwrapped to
/// the same form `extract_host_from_url` returns (for example `[::1]` → `::1`).
pub(crate) fn normalize_policy_host(pattern: &str) -> String {
    if pattern == "*" || pattern.starts_with("*.") {
        return pattern.to_string();
    }
    if let Some(host) = extract_host_from_url(pattern) {
        return host;
    }
    if pattern.starts_with('[')
        && let Some(end) = pattern.find(']')
    {
        let inner = &pattern[1..end];
        if !inner.is_empty() {
            return inner.to_ascii_lowercase();
        }
    }
    if let Some((host, port)) = pattern.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.to_string();
    }
    pattern.to_string()
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

    // IPv6 host: "[...]"
    let host_str = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        &host_port[1..end]
    } else {
        // Port is separated by ':' from the left for IPv4/hostname
        host_port.split(':').next()?
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

    Some(crate::policy::canonicalize_policy_host(&decoded))
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
