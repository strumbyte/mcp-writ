use super::*;

#[cfg(test)]
mod input_responses_mode_tests {
    use super::{InputResponsesMode, ResolvedInputResponses};

    #[test]
    fn parse_and_as_str_roundtrip() {
        for raw in ["auto", "deny", "allow", "inspect"] {
            let mode = InputResponsesMode::parse_kdl(raw).unwrap();
            assert_eq!(mode.as_str(), raw);
            match mode {
                InputResponsesMode::Auto => assert_eq!(raw, "auto"),
                InputResponsesMode::Deny => assert_eq!(raw, "deny"),
                InputResponsesMode::Allow => assert_eq!(raw, "allow"),
                InputResponsesMode::Inspect => assert_eq!(raw, "inspect"),
            }
        }
        assert!(InputResponsesMode::parse_kdl("maybe").is_err());
    }

    #[test]
    fn side_effect_parse_and_as_str_roundtrip() {
        for raw in ["read_only", "write", "network", "execute"] {
            let se = super::SideEffect::parse(raw).unwrap();
            assert_eq!(se.as_str(), raw);
            match se {
                super::SideEffect::ReadOnly => assert_eq!(raw, "read_only"),
                super::SideEffect::Write => assert_eq!(raw, "write"),
                super::SideEffect::Network => assert_eq!(raw, "network"),
                super::SideEffect::Execute => assert_eq!(raw, "execute"),
            }
        }
        let err = super::SideEffect::parse("mutate").unwrap_err();
        assert!(err.contains("unknown side_effect"));
    }

    #[test]
    fn resolve_auto_depends_on_schema() {
        assert_eq!(
            InputResponsesMode::Auto.resolve(true),
            ResolvedInputResponses::Deny
        );
        assert_eq!(
            InputResponsesMode::Auto.resolve(false),
            ResolvedInputResponses::Allow
        );
    }
}

#[cfg(test)]
mod bind_to_server_tests {
    use super::*;
    use crate::error::PolicyError;

    #[test]
    fn mixed_named_and_unnamed_is_validation_error() {
        let mut policy = default_policy();
        let mut named = ToolPolicy::named("read_file", true);
        named.server = Some("fs".into());
        policy.tools.push(named);
        policy.tools.push(ToolPolicy::named("other", true));
        let err = policy.bind_to_server(Some("fs")).unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn named_only_filters_to_selected_server() {
        let mut policy = default_policy();
        let mut a = ToolPolicy::named("a", true);
        a.server = Some("fs".into());
        let mut b = ToolPolicy::named("b", true);
        b.server = Some("git".into());
        policy.tools.push(a);
        policy.tools.push(b);
        let bound = policy.bind_to_server(Some("fs")).unwrap();
        assert_eq!(bound.tools.len(), 1);
        assert_eq!(bound.tools[0].name, "a");
    }
}

#[cfg(test)]
mod host_canonicalization_tests {
    use super::canonicalize_policy_host;

    #[test]
    fn dotted_decimal_roundtrips() {
        assert_eq!(canonicalize_policy_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(canonicalize_policy_host("010.0.0.1"), "8.0.0.1");
        assert_eq!(canonicalize_policy_host("0x7f.0.0.1"), "127.0.0.1");
    }

    /// WHATWG folds the final number into the remaining width —
    /// `1.256` is `1.0.1.0`, and a denylist entry for the folded
    /// address covers every equivalent spelling.
    #[test]
    fn whatwg_wide_final_component_folds() {
        assert_eq!(canonicalize_policy_host("1.256"), "1.0.1.0");
        assert_eq!(canonicalize_policy_host("1.0x100"), "1.0.1.0");
        assert_eq!(canonicalize_policy_host("127.1"), "127.0.0.1");
        assert_eq!(canonicalize_policy_host("2130706433"), "127.0.0.1");
        assert_eq!(canonicalize_policy_host("1.65535"), "1.0.255.255");
    }

    /// A bare `0x`/`0X` is the WHATWG number 0 — it folds like every
    /// other numeric spelling instead of slipping through as a DNS name.
    #[test]
    fn bare_hex_prefix_is_numeric() {
        assert_eq!(canonicalize_policy_host("0x"), "0.0.0.0");
        assert_eq!(canonicalize_policy_host("0X"), "0.0.0.0");
        assert_eq!(canonicalize_policy_host("127.0x"), "127.0.0.0");
    }

    /// Non-final parts above 255, extra components, and unparseable
    /// numbers keep their spelling — unmatchable rather than folded.
    #[test]
    fn invalid_ipv4_spellings_are_not_folded() {
        assert_eq!(canonicalize_policy_host("256.1.1.1"), "256.1.1.1");
        assert_eq!(canonicalize_policy_host("1.2.3.4.5"), "1.2.3.4.5");
        assert_eq!(canonicalize_policy_host("0xGG.0.0.1"), "0xgg.0.0.1");
        assert_eq!(canonicalize_policy_host("08.0.0.1"), "08.0.0.1");
    }

    /// IPv6 literals fold to their compressed canonical form;
    /// `::ffff:`-mapped literals become the IPv4 they actually address.
    #[test]
    fn ipv6_spellings_fold_to_canonical() {
        assert_eq!(canonicalize_policy_host("::1"), "::1");
        assert_eq!(canonicalize_policy_host("0:0:0:0:0:0:0:1"), "::1");
        assert_eq!(canonicalize_policy_host("[0:0::1]"), "::1");
        assert_eq!(canonicalize_policy_host("::ffff:7f00:1"), "127.0.0.1");
        assert_eq!(canonicalize_policy_host("[::ffff:127.0.0.1]"), "127.0.0.1");
    }

    /// Unicode domain names fold to their IDNA (Punycode) spelling —
    /// the same form a URL-parsed host already carries — so either
    /// spelling of a denylist entry matches the same wire host. An
    /// invalid IDN gets no ASCII form: it keeps its lowercase spelling
    /// and stays unmatchable rather than producing a partial result.
    #[test]
    fn idn_spellings_fold_to_punycode() {
        assert_eq!(canonicalize_policy_host("bücher.de"), "xn--bcher-kva.de");
        assert_eq!(canonicalize_policy_host("BÜCHER.de"), "xn--bcher-kva.de");
        // A wildcard deny normalizes its suffix the same way.
        assert_eq!(
            canonicalize_policy_host("*.bücher.de"),
            "*.xn--bcher-kva.de"
        );
        // Punycode spellings are already ASCII — passthrough lowercase.
        assert_eq!(
            canonicalize_policy_host("xn--bcher-kva.de"),
            "xn--bcher-kva.de"
        );
        // `_` is not valid in a domain label — UTS-46 rejects it and the
        // lowercase fallback stands (never equal to a parsed host).
        assert_eq!(
            canonicalize_policy_host("_dmarc.example.com"),
            "_dmarc.example.com"
        );
        // UTS-46 maps full-width digits to ASCII — the resulting
        // `127.1` is a WHATWG IPv4 spelling and must fold like the
        // ASCII form would.
        assert_eq!(canonicalize_policy_host("１２７.１"), "127.0.0.1");
    }

    /// A host the URL grammar cannot represent keeps its trimmed
    /// lowercase form — it never equals a parsed host.
    #[test]
    fn unrepresentable_hosts_stay_unmatchable() {
        assert_eq!(canonicalize_policy_host("EXAMPLE.com"), "example.com");
        assert_eq!(canonicalize_policy_host("example.com."), "example.com");
    }
}
