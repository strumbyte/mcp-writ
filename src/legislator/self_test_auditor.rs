use crate::auditor::checker::{self, PolicyViolation};
use crate::legislator::self_test::AuditorProbe;
use crate::policy::{Policy, ToolPolicy};
use crate::protocol::parse_jsonrpc_error;

/// JSON-RPC code used by the Auditor for policy denials (`proxy.rs`).
const POLICY_VIOLATION_ERROR_CODE: i64 = -32001;

const SECRET_PATH_PROBE_KEYS: &[&str] = &["path", "file", "uri", "filepath", "filename", "target"];

/// A raw JSON literal embedded without extra quoting.
struct RawLiteral(String);

impl nojson::DisplayJson for RawLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// Run the three Auditor probes against `policy` (no child required).
///
/// Uses the same `check_request` path as the proxy C2S Auditor. A probe that
/// cannot be exercised against the draft (schema accepts extra keys, no
/// filesystem argument slot) is `skipped`, not `fail`.
pub fn evaluate_auditor_probes(policy: &Policy) -> Vec<AuditorProbe> {
    let mut probes = Vec::new();
    probes.push(probe_deny_tool(policy));
    if let Some(probe) = probe_out_of_schema(policy) {
        probes.push(probe);
    }
    if policy.fs.secret_overlay {
        probes.push(probe_secret_path(policy));
    }
    probes
}

fn probe_deny_tool(policy: &Policy) -> AuditorProbe {
    let name = policy
        .tools
        .iter()
        .find(|t| !t.allowed)
        .map(|t| t.name.as_str())
        .unwrap_or("__mcp_writ_self_test_denied");
    let line = build_tools_call(1, name, r#"{"path":"/tmp/mcp-writ-self-test"}"#);
    expect_policy_error("deny-tool", &line, policy)
}

fn probe_out_of_schema(policy: &Policy) -> Option<AuditorProbe> {
    let tool = policy
        .tools
        .iter()
        .find(|t| t.allowed && t.args_schema.is_some())?;
    let attempts = [
        "{}",
        r#"{"path":1}"#,
        r#"{"__mcp_writ_not_in_schema":true}"#,
    ];
    for args in attempts {
        let line = build_tools_call(2, &tool.name, args);
        match checker::check_request(&line, policy) {
            Err(PolicyViolation { reason, .. }) if reason.contains("schema validation failed") => {
                return Some(expect_policy_error("out-of-schema", &line, policy));
            }
            Err(_) | Ok(_) => {}
        }
    }
    Some(AuditorProbe::skip(
        "out-of-schema",
        format!(
            "args_schema on '{}' did not reject empty, wrong-type, or extra-key probes",
            tool.name
        ),
    ))
}

fn probe_secret_path(policy: &Policy) -> AuditorProbe {
    let Some(tool) = first_allowed_tool(policy) else {
        return AuditorProbe::skip("secret-path", "no allowed tool".to_string());
    };
    let secret = "/workspace/.ssh/id_rsa";
    for key in SECRET_PATH_PROBE_KEYS {
        let args = format!(r#"{{"{key}":"{secret}"}}"#);
        let line = build_tools_call(3, &tool.name, &args);
        match checker::check_request(&line, policy) {
            Err(PolicyViolation { reason, .. }) => {
                if reason.contains("secret-path overlay") || reason.contains("secret-overlay") {
                    return expect_policy_error("secret-path", &line, policy);
                }
            }
            Ok(_) => {
                return AuditorProbe::fail(
                    "secret-path",
                    format!("request with {key}={secret} was allowed"),
                );
            }
        }
    }
    AuditorProbe::skip(
        "secret-path",
        format!(
            "no argument key among {SECRET_PATH_PROBE_KEYS:?} exercised the overlay on '{}'",
            tool.name
        ),
    )
}

pub(crate) fn first_allowed_tool(policy: &Policy) -> Option<&ToolPolicy> {
    policy
        .tools
        .iter()
        .find(|t| t.allowed && t.name == "read_file")
        .or_else(|| policy.tools.iter().find(|t| t.allowed))
}

fn expect_policy_error(name: &'static str, line: &str, policy: &Policy) -> AuditorProbe {
    match checker::check_request(line, policy) {
        Err(PolicyViolation { reason, .. }) => {
            let response = build_policy_error_response(1, name, &reason);
            if is_policy_jsonrpc_error(&response) {
                AuditorProbe::pass(
                    name,
                    format!("checker policy error (not a live proxy observation): {reason}"),
                )
            } else {
                AuditorProbe::fail(
                    name,
                    "denied but response was not a JSON-RPC policy error".to_string(),
                )
            }
        }
        Ok(_) => AuditorProbe::fail(
            name,
            "request was allowed (expected JSON-RPC policy error)".to_string(),
        ),
    }
}

pub fn build_tools_call(id: i64, tool: &str, arguments_raw: &str) -> String {
    let args = RawLiteral(arguments_raw.to_string());
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", id)?;
        f.member("method", "tools/call")?;
        f.member(
            "params",
            nojson::object(|p| {
                p.member("name", tool)?;
                p.member("arguments", &args)
            }),
        )
    })
    .to_string()
}

fn build_policy_error_response(id: i64, tool_name: &str, reason: &str) -> String {
    let message = format!("Policy violation: tool '{tool_name}' is not allowed ({reason})");
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", id)?;
        f.member(
            "error",
            nojson::object(|ef| {
                ef.member("code", POLICY_VIOLATION_ERROR_CODE)?;
                ef.member("message", message.as_str())
            }),
        )
    })
    .to_string()
}

pub fn is_policy_jsonrpc_error(line: &str) -> bool {
    match parse_jsonrpc_error(line) {
        Some(err) => {
            err.code == POLICY_VIOLATION_ERROR_CODE || err.message.contains("Policy violation")
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legislator::self_test::{AuditorVerdict, auditor_verdict};
    use crate::policy::kdl_loader::parse_kdl_policy;

    fn draft_with_read_file_schema() -> Policy {
        let kdl = r##"
            policy version=1
            defaults {
                filesystem {
                    secret-overlay #true
                }
            }
            server "auto-generated" {
                tool "read_file" side_effect="read_only" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
                tool "evil" deny=#true
            }
        "##;
        parse_kdl_policy(kdl).unwrap()
    }

    #[test]
    fn deny_tool_is_auditor_pass() {
        let policy = draft_with_read_file_schema();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes.iter().any(|p| p.name == "deny-tool" && p.passed),
            "{probes:?}"
        );
        assert_eq!(auditor_verdict(&probes), AuditorVerdict::Pass);
    }

    #[test]
    fn out_of_schema_and_secret_path_are_policy_errors() {
        let policy = draft_with_read_file_schema();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes.iter().any(|p| p.name == "out-of-schema" && p.passed),
            "{probes:?}"
        );
        assert!(
            probes.iter().any(|p| p.name == "secret-path" && p.passed),
            "{probes:?}"
        );
    }

    #[test]
    fn secret_path_skip_when_no_allowed_tool() {
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #true } }
            server "t" { tool "evil" deny=#true }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes
                .iter()
                .any(|p| p.name == "secret-path" && p.skipped && !p.passed),
            "secret-path must be skipped when no allowed tool exists: {probes:?}"
        );
        assert!(probes.iter().any(|p| p.name == "deny-tool" && p.passed));
        assert_eq!(auditor_verdict(&probes), AuditorVerdict::Pass);
    }

    #[test]
    fn out_of_schema_ignores_missing_path_rejection() {
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #false } }
            server "t" {
                tool "read_file" side_effect="read_only" args_schema="{\"type\":\"object\",\"properties\":{\"note\":{\"type\":\"string\"}}}" {
                    filesystem { allow "/workspace/**" }
                }
                tool "evil" deny=#true
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes
                .iter()
                .any(|p| p.name == "out-of-schema" && p.skipped),
            "missing path target must not count as out-of-schema: {probes:?}"
        );
        assert_eq!(auditor_verdict(&probes), AuditorVerdict::Pass);
    }

    #[test]
    fn out_of_schema_is_skipped_when_schema_cannot_reject() {
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #false } }
            server "t" {
                tool "echo" side_effect="read_only" args_schema="{\"type\":\"object\"}"
                tool "evil" deny=#true
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes
                .iter()
                .any(|p| p.name == "out-of-schema" && p.skipped),
            "open object schema must skip out-of-schema, not fail: {probes:?}"
        );
        assert_eq!(auditor_verdict(&probes), AuditorVerdict::Pass);
    }

    #[test]
    fn secret_path_probe_tries_file_key() {
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #true } }
            server "t" {
                tool "read_file" side_effect="read_only" args_schema="{\"type\":\"object\",\"properties\":{\"file\":{\"type\":\"string\"}},\"required\":[\"file\"],\"additionalProperties\":false}"
                tool "evil" deny=#true
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        let probes = evaluate_auditor_probes(&policy);
        assert!(
            probes.iter().any(|p| p.name == "secret-path" && p.passed),
            "secret-path must succeed via file= when path is not in schema: {probes:?}"
        );
    }
}
