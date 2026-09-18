/// Parse an environment variable value as either a JSON array of strings or
/// a simple shell-style split on whitespace.
///
/// - If the trimmed value starts with `[`, attempt to parse as a JSON array
///   using nojson (no serde). Each element is expected to be a string.
///   A parsed array that contains a non-string element is an error.
/// - Otherwise, split on whitespace.
/// - Empty/blank input returns an empty Vec.
pub fn parse_shell_or_json(input: &str) -> Result<Vec<String>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[')
        && let Ok(json) = nojson::RawJson::parse(trimmed)
        && let Ok(iter) = json.value().to_array()
    {
        let mut items = Vec::new();
        for elem in iter {
            match elem.to_unquoted_string_str() {
                Ok(s) => items.push(s.into_owned()),
                Err(_) => {
                    return Err(
                        "JSON array contains a non-string element; expected an array of strings"
                            .to_string(),
                    );
                }
            }
        }
        return Ok(items);
    }

    match shlex::split(trimmed) {
        Some(args) => Ok(args),
        None => {
            let preview = if trimmed.chars().count() > 20 {
                format!("{}...", trimmed.chars().take(20).collect::<String>())
            } else {
                trimmed.to_string()
            };
            Err(format!(
                "failed to parse shell string (unmatched quote?): {preview}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        assert!(parse_shell_or_json("").unwrap().is_empty());
        assert!(parse_shell_or_json("   ").unwrap().is_empty());
    }

    #[test]
    fn test_parse_shell_split() {
        let result = parse_shell_or_json("node server.js --port 3000").unwrap();
        assert_eq!(result, vec!["node", "server.js", "--port", "3000"]);
    }

    #[test]
    fn test_parse_shell_split_with_quotes() {
        let result = parse_shell_or_json(r#"echo "hello world" --flag"#).unwrap();
        assert_eq!(result, vec!["echo", "hello world", "--flag"]);
    }

    #[test]
    fn test_parse_shell_split_unclosed_quote() {
        assert!(parse_shell_or_json(r#"node "server.js"#).is_err());
    }

    #[test]
    fn test_parse_unclosed_quote_multibyte_preview() {
        let input = format!("{}\"", "あ".repeat(25));
        let err = parse_shell_or_json(&input).unwrap_err();
        assert!(err.contains("failed to parse shell string"));
    }

    #[test]
    fn test_parse_json_array() {
        let result = parse_shell_or_json(r#"["python3", "-m", "mcp_server"]"#).unwrap();
        assert_eq!(result, vec!["python3", "-m", "mcp_server"]);
    }

    #[test]
    fn test_parse_json_single_element() {
        let result = parse_shell_or_json(r#"["/usr/bin/node"]"#).unwrap();
        assert_eq!(result, vec!["/usr/bin/node"]);
    }

    #[test]
    fn test_parse_json_empty_array() {
        let result = parse_shell_or_json("[]").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_json_array_non_string_is_error() {
        let err = parse_shell_or_json(r#"[1, "ok"]"#).unwrap_err();
        assert!(err.contains("non-string"));
    }

    #[test]
    fn test_parse_combined_entrypoint_and_cmd() {
        let entrypoint = parse_shell_or_json(r#"["python3"]"#).unwrap();
        let cmd = parse_shell_or_json(r#"["app.py", "--verbose"]"#).unwrap();
        let mut argv = entrypoint;
        argv.extend(cmd);
        assert_eq!(argv, vec!["python3", "app.py", "--verbose"]);
    }

    #[test]
    fn test_parse_json_array_escaped_strings() {
        let input = r#"["python3", "-c", "print(\"hello\")"]"#;
        let result = parse_shell_or_json(input).unwrap();
        assert_eq!(result, vec!["python3", "-c", "print(\"hello\")"]);

        let win_input = r#"["tool", "--path", "C:\\workspace\\data"]"#;
        let win_result = parse_shell_or_json(win_input).unwrap();
        assert_eq!(win_result, vec!["tool", "--path", r#"C:\workspace\data"#]);
    }
}
