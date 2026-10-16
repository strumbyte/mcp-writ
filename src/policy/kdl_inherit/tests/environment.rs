use super::*;

// ── environment (defaults.environment) ─────────────────────

#[test]
fn test_environment_absent_everywhere_stays_restricted() {
    let dir = make_test_dir("env_absent");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    // Undeclared everywhere: restricted base environment, no ambient
    // inheritance (that now needs `inherit-parent #true`).
    assert!(policy.environment.restrict);
    assert!(!policy.environment.inherit_parent);
    assert!(policy.environment.allowed.is_empty());
}

#[test]
fn test_extends_inherits_base_environment() {
    let dir = make_test_dir("extends_env_inherit");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "MEMORY_FILE_PATH"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(policy.environment.restrict);
    assert_eq!(policy.environment.allowed, vec!["MEMORY_FILE_PATH"]);
}

#[test]
fn test_extends_environment_overlay_replaces_nonempty() {
    let dir = make_test_dir("extends_env_replace");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "A" "B"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                environment {
                    allow "C"
                }
            }
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(policy.environment.restrict);
    assert_eq!(policy.environment.allowed, vec!["C"]);
}

#[test]
fn test_extends_environment_empty_overlay_replaces_base_list() {
    // A declared `environment {}` is authoritative: the base's allow
    // list is replaced even by an empty one. Restriction itself can
    // still not be removed via extends.
    let dir = make_test_dir("extends_env_empty");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "A"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                environment {
                }
            }
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(policy.environment.restrict);
    assert!(policy.environment.allowed.is_empty());
}

#[test]
fn test_include_environment_merges() {
    let dir = make_test_dir("include_env");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "INCLUDED_VAR"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            include "extra.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    assert!(policy.environment.restrict);
    assert_eq!(policy.environment.allowed, vec!["INCLUDED_VAR"]);
}

#[test]
fn test_when_environment_replaces_allow_list() {
    let dir = make_test_dir("when_env_replace");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "A" "B"
                }
            }
            when environment="production" {
                defaults {
                    environment {
                        allow "C"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    assert!(policy.environment.restrict);
    assert_eq!(policy.environment.allowed, vec!["C"]);

    // A non-matching environment never applies the block.
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    assert_eq!(dev.environment.allowed, vec!["A", "B"]);
}

#[test]
fn test_when_environment_enables_restriction() {
    let dir = make_test_dir("when_env_enable");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            when environment="production" {
                defaults {
                    environment {
                        allow "A"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let prod = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    assert!(prod.environment.restrict);
    assert_eq!(prod.environment.allowed, vec!["A"]);

    // A non-matching `when` leaves the policy's environment undeclared
    // — which still means restricted: ambient parent inheritance is an
    // `inherit-parent` opt-in, never the omitted default.
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    assert!(dev.environment.restrict);
    assert!(!dev.environment.inherit_parent);
    assert!(dev.environment.allowed.is_empty());
}

#[test]
fn test_include_when_environment_empty_overlay_replaces() {
    // `environment {}` declared via a matching `when` inside an
    // included file stays authoritative across the merge — the empty
    // allow list replaces the inherited one instead of being read as
    // "nothing declared" and silently widened back to the base's list.
    let dir = make_test_dir("inc_when_env_empty");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                environment {
                    allow "A" "B"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("layer.kdl"),
        r#"
            policy version=1
            when environment="production" {
                defaults {
                    environment {
                    }
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            extends "base.kdl"
            include "layer.kdl"
        "#,
    )
    .unwrap();

    let prod = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    assert!(prod.environment.restrict);
    assert!(
        prod.environment.allowed.is_empty(),
        "empty environment from an included when must replace: {:?}",
        prod.environment.allowed
    );

    // The `when` never matched here — the inherited list survives.
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    assert_eq!(dev.environment.allowed, vec!["A", "B"]);
}

#[test]
fn test_when_tool_environment_is_validation_error() {
    // Same fail-closed rule as per-tool syscalls: `environment` under a
    // tool inside `when` must surface the load error, not be dropped.
    let dir = make_test_dir("when_tool_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    tool "fetch" {
                        environment {
                            allow "SECRET"
                        }
                    }
                }
            }
        "#,
    )
    .unwrap();

    let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
    assert!(
        err.to_string().contains("per-tool environment"),
        "got: {err}"
    );

    load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
}

#[test]
fn test_profile_environment_is_rejected() {
    let dir = make_test_dir("profile_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            profile "p" {
                environment {
                    allow "SECRET"
                }
            }
            server "s1" {
                tool "fetch" profile="p"
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("only allowed under 'defaults'"),
        "got: {err}"
    );
}

#[test]
fn test_server_defaults_environment_is_rejected() {
    let dir = make_test_dir("server_defaults_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                server-defaults {
                    environment {
                        allow "SECRET"
                    }
                }
                tool "fetch"
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("only allowed under 'defaults'"),
        "got: {err}"
    );
}

#[test]
fn test_when_server_defaults_environment_is_rejected() {
    // `environment` inside a `when` block's server-defaults must fail to
    // load instead of being silently ignored.
    let dir = make_test_dir("when_sd_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    server-defaults {
                        environment {
                            allow "SECRET"
                        }
                    }
                    tool "fetch"
                }
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
    assert!(
        err.to_string().contains("environment"),
        "server-defaults environment in when must fail to load: {err}"
    );
    load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
}

#[test]
fn test_when_server_environment_is_rejected() {
    // `environment` directly under a `server` node inside `when` fails to
    // load: `parse_server_hashes` scans the `when` doc's server children
    // and rejects `environment` outright before validation runs.
    let dir = make_test_dir("when_server_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    environment {
                        allow "SECRET"
                    }
                    tool "fetch" {
                        filesystem {
                            allow none=#true
                            require-path #false
                        }
                    }
                }
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
    assert!(
        err.to_string().contains("environment"),
        "server-level environment in when must fail to load: {err}"
    );
    load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
}
