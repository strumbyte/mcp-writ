use super::*;
use crate::policy::kdl_loader::load_kdl_policy_for_target_scanned;
use crate::policy::provenance::{
    LoadDiagnostics, LoadWarning, LoadWarningKind, ProvOp, ReplaceMode,
};
use std::path::Path;

// ── PR-24: provenance, replacement warnings, strict schema ──────
//
// `extends`/`include`/`when` composition records who wrote each
// effective field; a later declaration that drops inherited entries
// surfaces as a `replaced` warning, and schema-lax spellings warn on
// v1 while v2 refuses.

fn linux_target() -> crate::execution::ExecutionTarget {
    crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    }
}

fn scanned(
    dir: &Path,
) -> (
    crate::policy::Policy,
    crate::policy::provenance::LoadDiagnostics,
) {
    load_kdl_policy_for_target_scanned(&dir.join("child.kdl"), "", &linux_target())
        .expect("scanned load failed")
}

fn warnings_of_kind(
    diag: &crate::policy::provenance::LoadDiagnostics,
    kind: LoadWarningKind,
) -> Vec<&crate::policy::provenance::LoadWarning> {
    diag.warnings.iter().filter(|w| w.kind == kind).collect()
}

// F-13: a child's `defaults.syscalls` replaces the parent's whole
// allow list — the load warns and the provenance names both files.
// (A child list that *contains* every parent entry drops nothing and
// records `set`, not `replace` — see below.)
#[test]
fn test_extends_syscalls_replace_records_and_warns() {
    let dir = make_test_dir("prov_syscalls_replace");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "write" "execve"
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
                syscalls {
                    allow "read" "execve" "getpid"
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) = scanned(&dir);
    // Semantics unchanged: the child's list wins wholesale.
    assert_eq!(policy.syscalls.allowed, vec!["read", "execve", "getpid"]);

    let prov = policy.provenance.as_ref().expect("provenance attached");
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == "defaults.syscalls" && r.op == ProvOp::Replace)
        .expect("replace record for defaults.syscalls");
    assert!(rec.file.ends_with("child.kdl"));
    assert_eq!(
        rec.replaced,
        vec![(dir.join("base.kdl"), 1)],
        "the parent's 'write' entry was dropped"
    );
    assert_eq!(rec.items, vec!["write"]);

    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert_eq!(replaced.len(), 1, "one replacement warning");
    let msg = &replaced[0].message;
    assert!(msg.contains("base.kdl"), "warning names the parent: {msg}");
    assert!(msg.contains("1"), "warning counts dropped entries: {msg}");
    assert!(replaced[0].file.ends_with("child.kdl"));
}

// A child `syscalls` list that keeps every parent entry drops
// nothing — recorded as `set`, and no replacement warning.
#[test]
fn test_extends_syscalls_superset_sets_without_warning() {
    let dir = make_test_dir("prov_syscalls_superset");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "execve"
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
                syscalls {
                    allow "read" "execve" "getpid"
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) = scanned(&dir);
    assert_eq!(policy.syscalls.allowed, vec!["read", "execve", "getpid"]);
    let prov = policy.provenance.as_ref().unwrap();
    assert!(
        prov.records
            .iter()
            .any(|r| r.field == "defaults.syscalls" && r.op == ProvOp::Set),
        "a superset declaration records `set`"
    );
    assert!(
        warnings_of_kind(&diag, LoadWarningKind::Replaced).is_empty(),
        "nothing dropped — no warning"
    );
}

// F-14: a child's `defaults.network` allow replaces the parent's
// allow side while filesystem allows union.
#[test]
fn test_extends_network_allow_replaces_fs_unions() {
    let dir = make_test_dir("prov_net_replace");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/base/ro"
                }
                network {
                    allow host="a.example.com"
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
                filesystem {
                    allow "/child/ro"
                }
                network {
                    allow host="b.example.com"
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) = scanned(&dir);
    assert_eq!(
        policy.network.outbound.allowed,
        vec!["b.example.com".to_string()],
        "network allow replaces"
    );
    assert!(
        policy.fs.read_only.contains(&"/base/ro".to_string())
            && policy.fs.read_only.contains(&"/child/ro".to_string()),
        "filesystem allow unions"
    );

    let prov = policy.provenance.as_ref().unwrap();
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == "defaults.network.allow" && r.op == ProvOp::Replace)
        .expect("replace record for defaults.network.allow");
    // `a.example.com` was tracked as one `describe`d spelling per
    // declared rule — the replacement dropped a single rule.
    assert_eq!(rec.replaced, vec![(dir.join("base.kdl"), 1)]);

    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert!(
        replaced
            .iter()
            .any(|w| w.message.contains("defaults.network.allow")),
        "network allow replacement warns"
    );
    assert!(
        !replaced.iter().any(|w| w.message.contains("filesystem")),
        "filesystem union must not warn"
    );
}

// One `describe`d spelling per declared rule: a qualified rule's flat
// projection is the same rule spelled again, so the replacement drops
// it once — while `proto=`/`port=`/`unix=` qualifiers the flat lists
// cannot express still reach the record through `describe`.
#[test]
fn test_extends_network_allow_counts_each_rule_once() {
    let dir = make_test_dir("prov_net_rule_spellings");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=2
            defaults {
                network {
                    allow cidr="192.0.2.0/24" proto="udp"
                    allow unix="/run/app.sock"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=2
            defaults {
                network {
                    allow host="b.example.com"
                }
            }
        "#,
    )
    .unwrap();

    let (policy, _diag) = scanned(&dir);
    let prov = policy.provenance.as_ref().unwrap();
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == "defaults.network.allow" && r.op == ProvOp::Replace)
        .expect("replace record for defaults.network.allow");
    assert_eq!(
        rec.replaced,
        vec![(dir.join("base.kdl"), 2)],
        "one dropped entry per declared rule — qualified and unix included"
    );
    assert_eq!(
        rec.items,
        vec![
            "unix=/run/app.sock".to_string(),
            "cidr=192.0.2.0/24 proto=udp".to_string()
        ]
    );
}

// A `when` block re-declaring the *same file's* list is a co-located
// override, not a cross-file loss: the provenance keeps the replace
// record, but the warning surface skips pairs whose contributor is
// the replacing file itself.
#[test]
fn test_when_same_file_replace_records_without_warning() {
    let dir = make_test_dir("prov_when_same_file");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="a.example.com"
                }
            }
            when environment="prod" {
                defaults {
                    network {
                        allow host="b.example.com"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) =
        load_kdl_policy_for_target_scanned(&dir.join("policy.kdl"), "prod", &linux_target())
            .expect("scanned load failed");
    assert_eq!(
        policy.network.outbound.allowed,
        vec!["b.example.com".to_string()],
        "the matching `when` allow list replaces"
    );

    let prov = policy.provenance.as_ref().unwrap();
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == "defaults.network.allow" && r.op == ProvOp::Replace)
        .expect("replace record for defaults.network.allow");
    assert_eq!(rec.replaced, vec![(dir.join("policy.kdl"), 1)]);
    assert!(
        warnings_of_kind(&diag, LoadWarningKind::Replaced).is_empty(),
        "a same-file `when` override does not warn"
    );
}

// Tool-level replace: a child re-declaring a tool's `filesystem`
// replaces the parent's allow list for that tool.
#[test]
fn test_tool_filesystem_replace_warns() {
    let dir = make_test_dir("prov_tool_fs");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "read_file" {
                    filesystem {
                        allow "/base/data"
                    }
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
            server "s" {
                tool "read_file" {
                    filesystem {
                        allow "/child/data"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) = scanned(&dir);
    let tool = policy.tools.iter().find(|t| t.name == "read_file").unwrap();
    let fs = tool.fs.as_ref().unwrap();
    assert_eq!(fs.allowed_paths, vec!["/child/data".to_string()]);

    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert!(
        replaced
            .iter()
            .any(|w| w.message.contains("read_file") || w.message.contains("filesystem")),
        "tool fs replacement warns: {replaced:?}"
    );
}

// Profile redefinition across files warns — the earlier layer is
// replaced wholesale.
#[test]
fn test_profile_redefinition_warns() {
    let dir = make_test_dir("prov_profile_redef");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            profile "net" {
                network {
                    allow host="a.example.com"
                }
            }
            server "s" {
                tool "fetch" profile="net"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            profile "net" {
                network {
                    allow host="b.example.com"
                }
            }
        "#,
    )
    .unwrap();

    let (_policy, diag) = scanned(&dir);
    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert!(
        replaced
            .iter()
            .any(|w| w.message.contains("profile") && w.message.contains("base.kdl")),
        "profile redefinition warns: {replaced:?}"
    );
}

// A child file that restates the *identical* profile layer loses
// nothing — it is a `set`, not a replacement warning.
#[test]
fn test_profile_identical_redefinition_does_not_warn() {
    let dir = make_test_dir("prov_profile_identical");
    let profile = r#"
        profile "net" {
            network {
                allow host="a.example.com"
            }
        }
    "#;
    std::fs::write(dir.join("base.kdl"), format!("policy version=1\n{profile}")).unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        format!("extends \"base.kdl\"\npolicy version=1\n{profile}"),
    )
    .unwrap();

    let (_policy, diag) = scanned(&dir);
    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert!(
        !replaced.iter().any(|w| w.message.contains("profile")),
        "identical profile restatement does not warn: {replaced:?}"
    );
}

// `ReplaceMode::enforce` gates the `replaced` warnings — `Refuse`
// names the replacing files, `Off`/`Warn` pass. The env-to-mode wiring
// is covered by the `MCP_WRIT_REPLACE_MODE` e2e cases.
#[test]
fn test_replace_mode_enforce() {
    let mut diag = LoadDiagnostics::default();
    assert!(ReplaceMode::Refuse.enforce(&diag).is_ok());

    diag.warnings.push(LoadWarning {
        kind: LoadWarningKind::Replaced,
        file: PathBuf::from("child.kdl"),
        line: Some(4),
        message: "replaced 2 'defaults.syscalls' entries declared by 'base.kdl'".into(),
    });
    diag.warnings.push(LoadWarning {
        kind: LoadWarningKind::Schema,
        file: PathBuf::from("child.kdl"),
        line: None,
        message: "unknown top-level node".into(),
    });
    let err = ReplaceMode::Refuse.enforce(&diag).unwrap_err();
    assert!(
        err.to_string().contains("replaced inherited entries")
            && err.to_string().contains("child.kdl:4"),
        "refuse names the replacing file: {err}"
    );
    assert!(ReplaceMode::Warn.enforce(&diag).is_ok());
    assert!(ReplaceMode::Off.enforce(&diag).is_ok());
}

// ── Strict schema (F-15, F-16) ──────────────────────────────────

fn write_both(dir: &Path, body: &str) {
    // `body` is the policy text after the `policy version=` line.
    std::fs::write(dir.join("v1.kdl"), format!("policy version=1\n{body}")).unwrap();
    std::fs::write(dir.join("v2.kdl"), format!("policy version=2\n{body}")).unwrap();
}

fn v1_schema_warnings(dir: &Path) -> crate::policy::provenance::LoadDiagnostics {
    let (_p, diag) = load_kdl_policy_for_target_scanned(&dir.join("v1.kdl"), "", &linux_target())
        .expect("v1 load should succeed with warnings");
    diag
}

fn v2_error(dir: &Path) -> String {
    load_kdl_policy_for_target_scanned(&dir.join("v2.kdl"), "", &linux_target())
        .map(|_| ())
        .expect_err("v2 must refuse")
        .to_string()
}

#[test]
fn test_strict_unknown_top_level_node() {
    let dir = make_test_dir("strict_top_level");
    write_both(&dir, "bogus {}\n");
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("bogus")),
        "v1 warns: {schema:?}"
    );
    let err = v2_error(&dir);
    assert!(err.contains("bogus"), "v2 refuses: {err}");
}

#[test]
fn test_strict_defaults_child_typo() {
    let dir = make_test_dir("strict_defaults_child");
    write_both(
        &dir,
        r#"defaults {
            filesytem {
                allow "/x"
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("filesytem")),
        "v1 warns on the misspelled child: {schema:?}"
    );
    assert!(v2_error(&dir).contains("filesytem"));
}

#[test]
fn test_strict_second_extends() {
    let dir = make_test_dir("strict_second_extends");
    std::fs::write(dir.join("base.kdl"), "policy version=1\n").unwrap();
    std::fs::write(
        dir.join("v1.kdl"),
        "extends \"base.kdl\"\nextends \"other.kdl\"\npolicy version=1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("v2.kdl"),
        "extends \"base.kdl\"\nextends \"other.kdl\"\npolicy version=2\n",
    )
    .unwrap();
    std::fs::write(dir.join("other.kdl"), "policy version=1\n").unwrap();
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema
            .iter()
            .any(|w| w.message.contains("duplicate 'extends'")),
        "v1 warns on the second extends: {schema:?}"
    );
    assert!(v2_error(&dir).contains("extends"));
}

#[test]
fn test_strict_extends_extra_argument() {
    let dir = make_test_dir("strict_extends_arg");
    std::fs::write(dir.join("base.kdl"), "policy version=1\n").unwrap();
    std::fs::write(
        dir.join("v1.kdl"),
        "extends \"base.kdl\" \"extra\"\npolicy version=1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("v2.kdl"),
        "extends \"base.kdl\" \"extra\"\npolicy version=2\n",
    )
    .unwrap();
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema
            .iter()
            .any(|w| w.message.contains("extra argument(s) on 'extends'")),
        "v1 warns on the extra argument: {schema:?}"
    );
    assert!(v2_error(&dir).contains("extends"));
}

#[test]
fn test_strict_unknown_transport() {
    let dir = make_test_dir("strict_transport");
    write_both(&dir, "transport type=\"carrier-pigeon\"\n");
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("carrier-pigeon")),
        "v1 warns on the unknown transport: {schema:?}"
    );
    assert!(v2_error(&dir).contains("carrier-pigeon"));
}

#[test]
fn test_strict_when_unknown_attribute() {
    let dir = make_test_dir("strict_when_attr");
    write_both(
        &dir,
        r#"when environment="prod" bogus="x" {
            defaults {
                syscalls {
                    allow "execve"
                }
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("bogus")),
        "v1 warns on the unknown when attribute: {schema:?}"
    );
    assert!(v2_error(&dir).contains("bogus"));
}

// F-15: `profile`/`profiles` with extra arguments, a non-string
// argument, or properties is refused on v2 and warns on v1.
#[test]
fn test_strict_profiles_extra_args() {
    let dir = make_test_dir("strict_profiles_args");
    write_both(
        &dir,
        r#"profile "p" {
            network {
                deny host="*"
            }
        }
        server "s" {
            tool "fetch" {
                profiles "p" "q"
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("profiles")),
        "v1 warns on the extra profile argument: {schema:?}"
    );
    assert!(v2_error(&dir).contains("profiles"));
}

#[test]
fn test_strict_profile_child_property() {
    let dir = make_test_dir("strict_profile_prop");
    write_both(
        &dir,
        r#"profile "p" {
            network {
                deny host="*"
            }
        }
        server "s" {
            tool "fetch" {
                profile "p" flag=#true
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("profile")),
        "v1 warns on the profile child property: {schema:?}"
    );
    assert!(v2_error(&dir).contains("profile"));
}

#[test]
fn test_strict_include_extra_args_and_duplicate_nodes() {
    let dir = make_test_dir("strict_dup_include");
    std::fs::write(dir.join("shared.kdl"), "policy version=1\n").unwrap();
    for v in [1u32, 2] {
        std::fs::write(
            dir.join(if v == 1 { "v1.kdl" } else { "v2.kdl" }),
            format!(
                "include \"shared.kdl\" \"extra.kdl\"\npolicy version={v}\nlogging level=\"info\"\nlogging level=\"warn\"\n"
            ),
        )
        .unwrap();
    }
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema
            .iter()
            .any(|w| w.message.contains("extra argument(s) on 'include'")),
        "v1 warns on the extra include argument: {schema:?}"
    );
    assert!(
        schema
            .iter()
            .any(|w| w.message.contains("duplicate 'logging'")),
        "v1 warns on the duplicate top-level node: {schema:?}"
    );
    assert!(v2_error(&dir).contains("include"));
}

#[test]
fn test_strict_duplicate_tool_and_server() {
    let dir = make_test_dir("strict_dup_tool");
    // A duplicate tool inside one server is refused on every version —
    // the parser's own name check was never silent (runs before the
    // strict pass, so the finding surface is the hard error itself).
    write_both(
        &dir,
        r#"server "s" {
            tool "t" side_effect="read_only"
            tool "t" deny=#true
        }
        "#,
    );
    for v in ["v1.kdl", "v2.kdl"] {
        let err = load_kdl_policy_for_target_scanned(&dir.join(v), "", &linux_target())
            .map(|_| ())
            .expect_err("duplicate tool refuses on every version");
        assert!(err.to_string().contains("duplicate tool"), "{v}: {err}");
    }

    // A duplicate `server` name at top level is silently shadowing —
    // the strict pass flags it.
    write_both(
        &dir,
        r#"server "s" {
            tool "t" side_effect="read_only"
        }
        server "s" {
            tool "u" deny=#true
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema
            .iter()
            .any(|w| w.message.contains("duplicate server 's'")),
        "v1 warns on the duplicate server: {schema:?}"
    );
    assert!(v2_error(&dir).contains("duplicate server"));
}

#[test]
fn test_strict_profile_layer_child_unknown() {
    let dir = make_test_dir("strict_layer_child");
    write_both(
        &dir,
        r#"profile "p" {
            bogus {}
        }
        server "s" {
            server-defaults {
                bogus {}
            }
            tool "t" profile="p"
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema
            .iter()
            .filter(|w| w.message.contains("bogus"))
            .count()
            >= 2,
        "v1 warns for both layer children: {schema:?}"
    );
    assert!(v2_error(&dir).contains("bogus"));
}

// The hash scan tolerates layer names directly under `server`, but no
// parser reads them there — `filesystem` is silently dropped, so the
// strict pass flags it instead of letting it stand unread.
#[test]
fn test_strict_server_unread_layer_child() {
    let dir = make_test_dir("strict_server_child");
    write_both(
        &dir,
        r#"server "s" {
            filesystem {
                allow "/x"
            }
            tool "t" side_effect="read_only"
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w
            .message
            .contains("unknown node 'filesystem' under 'server'")),
        "v1 warns on the unread server child: {schema:?}"
    );
    assert!(v2_error(&dir).contains("filesystem"));
}

// A single-file v2 policy still carries provenance for `policy
// resolve`; a single-file load does not warn (nothing to replace).
#[test]
fn test_single_file_provenance_no_replaced_warnings() {
    let dir = make_test_dir("prov_single");
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            policy version=2
            defaults {
                syscalls {
                    allow "execve" "read"
                }
            }
        "#,
    )
    .unwrap();
    let (policy, diag) = scanned(&dir);
    let prov = policy.provenance.as_ref().expect("provenance attached");
    assert!(
        prov.records.iter().any(|r| r.field == "defaults.syscalls"),
        "single-file writes recorded"
    );
    assert!(
        warnings_of_kind(&diag, LoadWarningKind::Replaced).is_empty(),
        "nothing replaced — no warning"
    );
}

// The execve diagnostic names the file that dropped it — the
// replacement F-13 hid behind "execve required".
#[test]
fn test_execve_error_names_replacing_file() {
    let dir = make_test_dir("prov_execve_diag");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "execve"
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
                syscalls {
                    allow "read"
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) = scanned(&dir);
    // The load itself succeeds (warn mode); the execve requirement
    // fires downstream — check the diagnostic building blocks.
    assert!(!policy.syscalls.allowed.iter().any(|s| s == "execve"));
    let prov = policy.provenance.as_ref().unwrap();
    let dropped = prov.dropped_from("defaults.syscalls", "execve");
    assert_eq!(
        dropped,
        vec![(dir.join("base.kdl"), dir.join("child.kdl"))],
        "dropped_from names contributor and replacer"
    );
    let replaced = warnings_of_kind(&diag, LoadWarningKind::Replaced);
    assert!(
        replaced.iter().any(|w| w.file.ends_with("child.kdl")),
        "warning names the replacing file"
    );
}

// A `deny "x"` beside `allow "x"` is the deny-wins rule, not a
// duplicate — the entry check keys on the directive too, so v1 stays
// silent and v2 still loads. (A profile carries the list so the load
// itself stays valid — per-tool `syscalls` is rejected outright.)
#[test]
fn test_syscalls_allow_deny_same_name_not_duplicate() {
    let dir = make_test_dir("strict_allow_deny_distinct");
    write_both(
        &dir,
        r#"profile "p" {
            syscalls {
                allow "read"
                deny "read"
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        !schema.iter().any(|w| w.message.contains("duplicate")),
        "allow/deny sharing a name is not a duplicate: {schema:?}"
    );
    load_kdl_policy_for_target_scanned(&dir.join("v2.kdl"), "", &linux_target())
        .expect("v2 loads — a deny beside an allow is legal");

    // …while a true duplicate is still caught.
    write_both(
        &dir,
        r#"profile "p" {
            syscalls {
                allow "read" "read"
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("duplicate")),
        "v1 warns on the true duplicate: {schema:?}"
    );
    assert!(v2_error(&dir).contains("duplicate"), "v2 refuses");
}

// `tool` child blocks get the same entry checks `profile`/
// `server-defaults` do — a duplicated allow inside a tool's
// `filesystem` warns on v1 and refuses on v2.
#[test]
fn test_tool_child_block_duplicate_entries_flagged() {
    let dir = make_test_dir("strict_tool_fs_dup");
    write_both(
        &dir,
        r#"server "s" {
            tool "t" {
                filesystem {
                    allow "/a"
                    allow "/a"
                }
            }
        }
        "#,
    );
    let diag = v1_schema_warnings(&dir);
    let schema = warnings_of_kind(&diag, LoadWarningKind::Schema);
    assert!(
        schema.iter().any(|w| w.message.contains("duplicate")),
        "v1 warns on the duplicated tool allow: {schema:?}"
    );
    assert!(v2_error(&dir).contains("duplicate"));
}

// A matching `when` that replaces `defaults.filesystem` must
// re-attribute the tool grant rematerialized from it — the tool
// field's writers are the defaults' writers, so `dropped_from` names
// base.kdl as the contributor the `when` dropped rather than leaving
// the stale seed the tool's own declaration wrote.
#[test]
fn test_when_fs_override_reattributes_tool_provenance() {
    let dir = make_test_dir("prov_when_tool_fs");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/base/data"
                }
            }
            server "s" {
                tool "t"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            when environment="prod" {
                defaults {
                    filesystem {
                        allow "/prod/data"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let (policy, _diag) =
        load_kdl_policy_for_target_scanned(&dir.join("child.kdl"), "prod", &linux_target())
            .expect("env-matched load");
    let field = "server \"s\".tool \"t\".filesystem.allowed";
    let prov = policy.provenance.as_ref().expect("provenance attached");
    assert_eq!(
        prov.dropped_from(field, "/base/data"),
        vec![(dir.join("base.kdl"), dir.join("child.kdl"))],
        "the lost materialized grant names the declaring file and the replacer"
    );
    let (writer, _line) = prov.field_writer(field).expect("the field was written");
    assert!(
        writer.ends_with("child.kdl"),
        "the rewritten tool allow is attributed to the `when` file"
    );
}

// A `when`-declared global deny pattern that covers a tool's own
// allow prunes it — recorded as a `prune` naming the deny's writer,
// and *not* as a replacement warning (a declared deny is the schema's
// own semantics). The deny is a glob covering the allow spelling, so
// exact-equality pruning would leave the grant — and the record —
// behind.
#[test]
fn test_when_global_deny_prunes_explicit_tool_allow() {
    let dir = make_test_dir("prov_when_deny_prunes");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "t" {
                    filesystem {
                        allow "/base/data"
                    }
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
            when environment="prod" {
                defaults {
                    filesystem {
                        deny "/base/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) =
        load_kdl_policy_for_target_scanned(&dir.join("child.kdl"), "prod", &linux_target())
            .expect("env-matched load");
    let field = "server \"s\".tool \"t\".filesystem.allowed";
    let tool = policy.tools.iter().find(|t| t.name == "t").unwrap();
    assert!(
        !tool
            .fs
            .as_ref()
            .unwrap()
            .allowed_paths
            .iter()
            .any(|p| p == "/base/data"),
        "the global deny pruned the tool's allow"
    );
    let prov = policy.provenance.as_ref().unwrap();
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == field && r.op == ProvOp::Prune)
        .expect("the deny-wins prune is recorded");
    assert!(rec.file.ends_with("child.kdl"));
    assert_eq!(rec.replaced, vec![(dir.join("base.kdl"), 1)]);
    assert!(
        warnings_of_kind(&diag, LoadWarningKind::Replaced)
            .iter()
            .all(|w| !w.message.contains("filesystem.allowed")),
        "a declared deny's prune is not a replacement warning"
    );
}

// The same deny-wins drop on a tool with no `filesystem` block: the
// materialized grant disappears, and rematerialization classifies the
// drop as a `prune` (deny-pattern coverage) rather than a `replace` —
// without it the lost grant would surface as a replacement warning.
#[test]
fn test_when_global_deny_prunes_materialized_tool_allow() {
    let dir = make_test_dir("prov_when_deny_prunes_inherited");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/base/data"
                }
            }
            server "s" {
                tool "t"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            when environment="prod" {
                defaults {
                    filesystem {
                        deny "/base/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let (policy, diag) =
        load_kdl_policy_for_target_scanned(&dir.join("child.kdl"), "prod", &linux_target())
            .expect("env-matched load");
    let field = "server \"s\".tool \"t\".filesystem.allowed";
    let tool = policy.tools.iter().find(|t| t.name == "t").unwrap();
    assert!(
        !tool
            .fs
            .as_ref()
            .map(|fs| fs.allowed_paths.iter().any(|p| p == "/base/data"))
            .unwrap_or(false),
        "the global deny pruned the materialized allow"
    );
    let prov = policy.provenance.as_ref().unwrap();
    let rec = prov
        .records
        .iter()
        .find(|r| r.field == field && r.op == ProvOp::Prune)
        .expect("the deny-wins prune is recorded");
    assert!(rec.file.ends_with("child.kdl"));
    assert_eq!(rec.replaced, vec![(dir.join("base.kdl"), 1)]);
    assert!(
        warnings_of_kind(&diag, LoadWarningKind::Replaced)
            .iter()
            .all(|w| !w.message.contains("filesystem.allowed")),
        "a declared deny's prune is not a replacement warning"
    );
}

// `when` integrity pins record the `server` node's line — the closest
// attribution the override carries — rather than `None`.
#[test]
fn test_when_integrity_overrides_record_server_line() {
    let dir = make_test_dir("prov_when_hash_line");
    let digest = "a".repeat(64);
    let content = format!(
        "policy version=1\nserver \"s\" {{\n    tool \"t\"\n}}\nwhen environment=\"prod\" {{\n    server \"s\" {{\n        binary-hash \"sha256:{digest}\" target=\"/bin/x\"\n        tools-list-hash \"sha256:{digest}\"\n    }}\n}}\n"
    );
    std::fs::write(dir.join("child.kdl"), &content).unwrap();
    // Line 6 is the `server "s"` node inside the `when` block.
    let server_line = content
        .lines()
        .enumerate()
        .find_map(|(i, l)| {
            (l.trim_start().starts_with("server \"s\"") && i > 3).then_some(i as u32 + 1)
        })
        .expect("the when-block server node");

    let (policy, _diag) =
        load_kdl_policy_for_target_scanned(&dir.join("child.kdl"), "prod", &linux_target())
            .expect("env-matched load");
    let prov = policy.provenance.as_ref().unwrap();
    for field in ["integrity.hash", "integrity.tools-list"] {
        let rec = prov
            .records
            .iter()
            .rev()
            .find(|r| r.field == field && r.file.ends_with("child.kdl"))
            .unwrap_or_else(|| panic!("the when-path {field} write is recorded"));
        assert_eq!(
            rec.line,
            Some(server_line),
            "{field} attributes the `server` node's line"
        );
    }
}
