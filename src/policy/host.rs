use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Normalize a policy host pattern to the hostname form used by the auditor.
///
/// URL values are reduced to the hostname. `host:port` is reduced to the host
/// only when the host is not an IPv6 literal. Bracketed IPv6 is unwrapped to
/// the same form `extract_host_from_url` returns (for example `[::1]` → `::1`).
pub(crate) fn normalize_policy_host(pattern: &str) -> String {
    analyze_policy_host(pattern).0
}

/// The normalization above plus the qualifier a port-aware mechanism can
/// act on: `(normalized_host, port, port_qualified)`. `port` is the
/// concrete destination port the spelling carried (`host:443`,
/// `[v6]:8443`, a URL authority port); `port_qualified` records that a
/// `:port` qualifier existed at all — including the empty `host:`/`[v6]:`
/// /`…:65536` spellings where no concrete port is representable. The port
/// folds away from the stored identity because the auditor's identity is
/// the host alone, but a mechanism that emits real destination rules
/// (PSEC, the namespaced proxy) needs both facts: the concrete port it
/// can pin, or the qualifier it must refuse rather than widen to every
/// port.
pub(crate) fn analyze_policy_host(pattern: &str) -> (String, Option<u16>, bool) {
    if pattern == "*" || pattern.starts_with("*.") {
        return (pattern.to_string(), None, false);
    }
    if let Some((host, port, port_qualified)) = extract_host_and_port_from_url(pattern) {
        return (host, port, port_qualified);
    }
    if pattern.starts_with('[')
        && let Some(end) = pattern.find(']')
    {
        let inner = &pattern[1..end];
        if !inner.is_empty() {
            // `[v6]` carries no port; `[v6]:port` does. A non-port suffix
            // keeps the folded-inner quirk of the pre-refactor shape.
            let suffix = &pattern[end + 1..];
            return (
                canonicalize_url_host(inner).unwrap_or_else(|| inner.to_ascii_lowercase()),
                port_suffix_port(suffix),
                valid_port_suffix(suffix),
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
            port.parse::<u16>().ok(),
            true,
        );
    }
    (
        canonicalize_url_host(pattern).unwrap_or_else(|| pattern.to_ascii_lowercase()),
        None,
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
    extract_host_and_port_from_url(url).map(|(host, _, _)| host)
}

/// `extract_host_from_url` plus the qualifier the authority carried:
/// `(host, port, port_qualified)` — `port` is `Some` only when the
/// authority spelled a representable `:port` (an empty `host:` suffix
/// still counts as qualified even though it defaults the port).
fn extract_host_and_port_from_url(url: &str) -> Option<(String, Option<u16>, bool)> {
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
    let (host_str, port, port_qualified) = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let rest = &host_port[end + 1..];
        if !rest.is_empty() && !valid_port_suffix(rest) {
            return None;
        }
        (&host_port[1..end], port_suffix_port(rest), !rest.is_empty())
    } else {
        match host_port.split_once(':') {
            Some((host, port)) => {
                if port.contains(':') || !valid_port(port) {
                    return None;
                }
                (host, port.parse::<u16>().ok(), true)
            }
            None => (host_port, None, false),
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
    canonicalize_url_host(&decoded).map(|host| (host, port, port_qualified))
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

/// The concrete port a `:port` suffix spells, when one is representable.
/// `":443"` → `Some(443)`; `""`/`":"` → `None` (no qualifier / empty
/// qualifier).
fn port_suffix_port(rest: &str) -> Option<u16> {
    rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok())
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

/// A `host=` value that is a canonical bare-port spelling — `allow
/// host="443"` is the documented port-only rule form (a `ConnectTcp`
/// netport grant; `proto="udp"`/`"any"` on the same node scopes the
/// transport). Only the canonical decimal form counts: leading zeros,
/// `0`, and out-of-range values are not ports — an all-digit `host` that
/// is not a valid port is a load error, never a host fold (folding it
/// through the WHATWG IPv4-number grammar once produced nonsense rules
/// like `0.0.1.187` for `443`).
pub(crate) fn bare_port_spelling(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || value.starts_with('0') {
        return None;
    }
    value.parse::<u16>().ok()
}

/// An all-ASCII-digit `host=` value — used to refuse the non-port forms
/// (`"0"`, `"0443"`, `"99999"`) with a load error rather than fold them
/// through the WHATWG IPv4-number grammar.
pub(crate) fn all_digits_host(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// CIDR rules (`allow cidr=` / `deny cidr=`) — the IP layer of the two-layer
// egress model.
// ---------------------------------------------------------------------------

/// Parse a policy `cidr=` attribute value into its canonical
/// `addr/prefix` rule plus whether the spelling carried a `:port`
/// qualifier.
///
/// Grammar: `v4/prefix`, `v4/prefix:port`, `v6/prefix`, or
/// `[v6/prefix]` optionally followed by `:port`. An unbracketed
/// `v6/prefix:port` is rejected — the port must be written
/// `[v6/prefix]:port`, matching the URL authority convention.
///
/// The stored form is canonical: IPv6 compresses to its `Display`
/// spelling, host bits are masked off, so `10.0.0.9/24` and
/// `10.0.0.0/24` normalize to the same rule and deduplicate, and an
/// IPv4-mapped IPv6 rule (`::ffff:a.b.c.d/p`, `p >= 96`) folds into
/// the IPv4 rule `a.b.c.d/(p-96)` it names — the IP layer compares
/// within one family, so a mapped spelling left unfolded would never
/// match. A mapped prefix below /96 also covers non-mapped space and
/// is rejected.
///
/// A bare IP literal (no `/`) is rejected: `host=` already covers
/// single addresses — a literal there stands as a static IP-layer rule
/// too — so `cidr` keeps its "address range" meaning unambiguous.
///
/// The qualifier the spelling carried rides in the middle of the return
/// tuple: `(canonical_rule, port, port_qualified)` — `port` is `Some`
/// only for a representable `:port` (`10.0.0.0/8:53`); `port_qualified`
/// records that any qualifier existed, including the empty `:` form a
/// port-aware mechanism must refuse rather than widen.
///
/// `Err(reason)` says why the spelling is not a CIDR rule; callers
/// wrap it in a `KdlParse` error.
pub(crate) fn analyze_policy_cidr(value: &str) -> Result<(String, Option<u16>, bool), String> {
    let v = value.trim();
    let (inner, mut port, mut port_qualified) = if let Some(rest) = v.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "unterminated '['".to_string())?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() && !valid_port_suffix(suffix) {
            return Err(format!("invalid suffix after ']' in '{v}'"));
        }
        (&rest[..end], port_suffix_port(suffix), !suffix.is_empty())
    } else {
        (v, None, false)
    };
    let (addr_str, tail) = inner.split_once('/').ok_or_else(|| {
        "expected '<addr>/<prefix>' (a single address belongs in 'host=')".to_string()
    })?;
    let prefix_str = match tail.split_once(':') {
        Some((prefix, port_str)) => {
            if addr_str.contains(':') {
                return Err(
                    "an IPv6 port qualifier must be bracketed: '[addr/prefix]:port'".to_string(),
                );
            }
            if !valid_port(port_str) {
                return Err(format!("invalid port qualifier in '{v}'"));
            }
            port = port_str.parse::<u16>().ok();
            port_qualified = true;
            prefix
        }
        None => tail,
    };
    if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid prefix length in '{v}'"));
    }
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| format!("invalid prefix length in '{v}'"))?;
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| format!("invalid IP address in '{v}'"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("prefix length {prefix} exceeds {max} in '{v}'"));
    }
    // An IPv4-mapped IPv6 rule (`::ffff:a.b.c.d/p`) names IPv4 space —
    // fold it into an IPv4 rule so it matches the IPv4 destinations it
    // actually covers (the IP layer compares within one family). A
    // mapped spelling with a prefix below /96 also covers non-mapped
    // space and cannot fold — reject it rather than narrow silently.
    let (addr, prefix) = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
            Some(_) => {
                return Err(format!(
                    "IPv4-mapped prefix length {prefix} below 96 in '{v}' also \
                     covers non-mapped space — write the IPv4 CIDR directly"
                ));
            }
            None => (addr, prefix),
        },
        _ => (addr, prefix),
    };
    Ok((
        format!("{}/{prefix}", mask_cidr_addr(addr, prefix)),
        port,
        port_qualified,
    ))
}

/// Mask `addr` to `prefix` bits — the canonical network address of a
/// CIDR rule.
fn mask_cidr_addr(addr: IpAddr, prefix: u32) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let keep = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & keep))
        }
        IpAddr::V6(v6) => {
            let keep = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & keep))
        }
    }
}

/// Parse a stored (canonical) `addr/prefix` rule back into
/// (address, prefix length). `None` for any other spelling — callers
/// treat `None` as "not an IP-layer rule", never as an error.
pub(crate) fn parse_policy_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (u32::from(prefix) <= max).then_some((addr, prefix))
}

fn v4_masked_eq(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let keep = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(a) & keep == u32::from(b) & keep
}

fn v6_masked_eq(a: Ipv6Addr, b: Ipv6Addr, prefix: u8) -> bool {
    let keep = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    u128::from(a) & keep == u128::from(b) & keep
}

/// Whether `addr` falls inside the canonical `cidr` rule.
pub(crate) fn cidr_contains(cidr: &str, addr: &IpAddr) -> bool {
    let Some((net, prefix)) = parse_policy_cidr(cidr) else {
        return false;
    };
    match (net, *addr) {
        (IpAddr::V4(net), IpAddr::V4(a)) => v4_masked_eq(net, a, prefix),
        (IpAddr::V6(net), IpAddr::V6(a)) => v6_masked_eq(net, a, prefix),
        _ => false,
    }
}

/// Whether the canonical rule `outer` covers `inner` entirely — same
/// family, `outer`'s prefix no longer, shared prefix bits.
pub(crate) fn cidr_covers(outer: &str, inner: &str) -> bool {
    let (Some((o, op)), Some((i, ip))) = (parse_policy_cidr(outer), parse_policy_cidr(inner))
    else {
        return false;
    };
    if op > ip {
        return false;
    }
    match (o, i) {
        (IpAddr::V4(o), IpAddr::V4(i)) => v4_masked_eq(o, i, op),
        (IpAddr::V6(o), IpAddr::V6(i)) => v6_masked_eq(o, i, op),
        _ => false,
    }
}

/// Whether the canonical cidr ranges `a` and `b` overlap at all —
/// used to refuse a deny carved inside an allowed range on mechanisms
/// that cannot express exceptions.
pub(crate) fn cidr_intersects(a: &str, b: &str) -> bool {
    let (Some((a, pa)), Some((b, pb))) = (parse_policy_cidr(a), parse_policy_cidr(b)) else {
        return false;
    };
    let prefix = pa.min(pb);
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => v4_masked_eq(a, b, prefix),
        (IpAddr::V6(a), IpAddr::V6(b)) => v6_masked_eq(a, b, prefix),
        _ => false,
    }
}

/// `true` when a normalized host-list entry is an IP literal — an
/// `allow host=`/`deny host=` on a literal needs no resolution, so the
/// same entry also stands as an IP-layer rule (`/32` or `/128`).
pub(crate) fn host_is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// The `addr/prefix` host-route form of an IP literal — the shape IP
/// layer rules carry (`/32` for IPv4, `/128` for IPv6).
pub(crate) fn ip_literal_cidr(addr: IpAddr) -> String {
    let prefix = if addr.is_ipv4() { 32 } else { 128 };
    format!("{addr}/{prefix}")
}

/// Check if a hostname matches a policy host pattern.
///
/// This is the single name-layer matching rule shared by the Auditor's
/// RPC argument checks and the DNS gate's query-name evaluation —
/// supports exact match, wildcard suffix (`*.example.com` matches
/// `sub.example.com` but not bare `example.com`), `*` match-all, and
/// normalizes URL/port-formatted spellings (e.g. `https://api.example.com`
/// or `api.example.com:443`) before comparing.
pub(crate) fn host_matches(host: &str, pattern: &str) -> bool {
    let host_lower = super::canonicalize_policy_host(&normalize_policy_host(host));
    let pat_lower = super::canonicalize_policy_host(pattern);

    if pat_lower == "*" {
        return true;
    }

    let pat_host = super::canonicalize_policy_host(&normalize_policy_host(&pat_lower));

    if host_lower == pat_host {
        return true;
    }
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return host_lower.ends_with(&with_dot);
    }
    false
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

    #[test]
    fn test_analyze_policy_cidr_basic() {
        assert_eq!(
            analyze_policy_cidr("10.0.0.0/8"),
            Ok(("10.0.0.0/8".to_string(), None, false))
        );
        assert_eq!(
            analyze_policy_cidr("192.0.2.0/24"),
            Ok(("192.0.2.0/24".to_string(), None, false))
        );
        assert_eq!(
            analyze_policy_cidr("2001:db8::/32"),
            Ok(("2001:db8::/32".to_string(), None, false))
        );
    }

    #[test]
    fn test_analyze_policy_cidr_masks_host_bits() {
        assert_eq!(
            analyze_policy_cidr("10.0.0.9/24"),
            Ok(("10.0.0.0/24".to_string(), None, false))
        );
        assert_eq!(
            analyze_policy_cidr("0.0.0.0/0"),
            Ok(("0.0.0.0/0".to_string(), None, false))
        );
        // An IPv4-mapped IPv6 spelling folds into the IPv4 rule it
        // names — prefix 104-96=8 after the mapping.
        assert_eq!(
            analyze_policy_cidr("::ffff:0a00:1/104"),
            Ok(("10.0.0.0/8".to_string(), None, false))
        );
        // A mapped prefix below /96 covers non-mapped space too and
        // refuses rather than narrowing into an IPv4 rule.
        assert!(analyze_policy_cidr("::ffff:0a00:1/95").is_err());
        assert_eq!(
            analyze_policy_cidr("::ffff:0a00:1/128"),
            Ok(("10.0.0.1/32".to_string(), None, false))
        );
    }

    #[test]
    fn test_analyze_policy_cidr_port_qualified() {
        assert_eq!(
            analyze_policy_cidr("10.0.0.0/8:443"),
            Ok(("10.0.0.0/8".to_string(), Some(443), true))
        );
        assert_eq!(
            analyze_policy_cidr("[2001:db8::/32]:443"),
            Ok(("2001:db8::/32".to_string(), Some(443), true))
        );
        assert_eq!(
            analyze_policy_cidr("[2001:db8::/32]"),
            Ok(("2001:db8::/32".to_string(), None, false))
        );
        // Unbracketed IPv6 port qualifier is rejected.
        assert!(analyze_policy_cidr("2001:db8::/32:443").is_err());
        // Malformed ports are rejected.
        assert!(analyze_policy_cidr("10.0.0.0/8:abc").is_err());
        assert!(analyze_policy_cidr("10.0.0.0/8:99999").is_err());
    }

    #[test]
    fn test_analyze_policy_cidr_rejects_invalid() {
        assert!(analyze_policy_cidr("").is_err());
        assert!(analyze_policy_cidr("10.0.0.1").is_err()); // bare literal → host=
        assert!(analyze_policy_cidr("example.com/24").is_err());
        assert!(analyze_policy_cidr("10.0.0.0/33").is_err());
        assert!(analyze_policy_cidr("2001:db8::/129").is_err());
        assert!(analyze_policy_cidr("10.0.0.0/-1").is_err());
        assert!(analyze_policy_cidr("10.0.0.0/x").is_err());
        assert!(analyze_policy_cidr("*.example.com/24").is_err());
    }

    #[test]
    fn test_cidr_contains() {
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(cidr_contains("10.0.0.0/8", &ip));
        assert!(!cidr_contains("10.0.0.0/8", &"11.0.0.9".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/0", &ip));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(cidr_contains("2001:db8::/32", &v6));
        assert!(!cidr_contains("2001:db8::/32", &ip)); // family mismatch
        assert!(!cidr_contains("10.0.0.0/8", &v6));
        assert!(!cidr_contains("not-a-cidr", &ip));
    }

    #[test]
    fn test_cidr_covers() {
        assert!(cidr_covers("10.0.0.0/8", "10.0.0.0/24"));
        assert!(cidr_covers("10.0.0.0/24", "10.0.0.0/24"));
        assert!(!cidr_covers("10.0.0.0/24", "10.0.0.0/8"));
        assert!(!cidr_covers("10.0.0.0/24", "10.0.1.0/24"));
        assert!(cidr_covers("0.0.0.0/0", "10.0.0.0/8"));
        assert!(cidr_covers("::/0", "2001:db8::/32"));
        assert!(!cidr_covers("0.0.0.0/0", "2001:db8::/32")); // family mismatch
    }

    #[test]
    fn test_cidr_intersects() {
        assert!(cidr_intersects("10.0.0.0/8", "10.0.0.0/24"));
        assert!(cidr_intersects("10.0.0.0/24", "10.0.0.0/8"));
        assert!(!cidr_intersects("10.0.0.0/24", "10.0.1.0/24"));
        assert!(!cidr_intersects("10.0.0.0/8", "2001:db8::/32"));
        assert!(cidr_intersects("10.0.0.0/8", "10.0.0.9/32"));
    }

    #[test]
    fn test_host_is_ip_literal() {
        assert!(host_is_ip_literal("10.0.0.1"));
        assert!(host_is_ip_literal("::1"));
        assert!(!host_is_ip_literal("example.com"));
        assert!(!host_is_ip_literal("*.example.com"));
        assert!(!host_is_ip_literal("443")); // bare port entry
    }

    #[test]
    fn test_ip_literal_cidr() {
        assert_eq!(ip_literal_cidr("10.0.0.1".parse().unwrap()), "10.0.0.1/32");
        assert_eq!(ip_literal_cidr("::1".parse().unwrap()), "::1/128");
    }
}
