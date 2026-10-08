use super::*;

#[test]
fn python_script_payload_matches_hash_helper() {
    let argv = vec!["python".into(), "server.py".into()];
    assert_eq!(crate::workload::first_payload_arg(&argv), Some("server.py"));
    let d = discover_from_argv(&argv);
    assert!(d.skips_native_elf());
    match d.kind {
        PayloadKind::Source { interpreter, path } => {
            assert_eq!(interpreter, InterpreterKind::Python);
            assert_eq!(path, PathBuf::from("server.py"));
        }
        other => panic!("expected Source, got {other:?}"),
    }
}

#[test]
fn python3_and_versioned_interpreters() {
    for cmd in [
        "python3",
        "python3.12",
        "/usr/bin/python3",
        "C:\\Python\\python.exe",
        "py",
        "py.exe",
        "C:\\Windows\\py.exe",
        "pythonw",
        "pyw",
        "PYTHON.EXE",
        "py.eXe",
    ] {
        let argv = vec![cmd.into(), "app.py".into()];
        assert!(
            matches!(
                discover_from_argv(&argv).kind,
                PayloadKind::Source {
                    interpreter: InterpreterKind::Python,
                    ..
                }
            ),
            "{cmd}"
        );
    }
    let launcher = discover_from_argv(&["py".into(), "-3".into(), "server.py".into()]);
    match launcher.kind {
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            path,
        } => {
            assert_eq!(path, PathBuf::from("server.py"));
        }
        other => panic!("expected Source for py -3 server.py, got {other:?}"),
    }
    assert_eq!(
        crate::workload::first_payload_arg(&["py".into(), "-3".into(), "server.py".into()]),
        Some("server.py")
    );
}

#[test]
fn node_and_npx_skip_elf() {
    let node = discover_from_argv(&["node".into(), "index.js".into()]);
    assert!(matches!(
        node.kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            ..
        }
    ));
    let npx = discover_from_argv(&["npx".into(), "@scope/pkg".into()]);
    assert!(npx.skips_native_elf());
    assert!(matches!(npx.kind, PayloadKind::Unresolved { .. }));
    let mixed_case = discover_from_argv(&["Node.ExE".into(), "index.js".into()]);
    assert!(matches!(
        mixed_case.kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn delegating_launcher_script_ignores_its_own_shebang() {
    // A launcher spelled `env` that is itself a script: the kernel
    // runs the script's interpreter, but that interpreter never
    // binds the workload `env` resolves to — the discovery must
    // stay Unresolved rather than Source.
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("env");
    std::fs::write(&script, "#!/bin/sh\n").expect("write script");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let argv = vec![script.to_string_lossy().to_string()];
    match discover_from_argv(&argv).kind {
        PayloadKind::Unresolved { .. } => {}
        other => panic!("expected Unresolved for delegating launcher, got {other:?}"),
    }

    // Contrast: the same shebang on a non-delegating name still
    // classifies as interpreter source.
    let runner = dir.path().join("runner");
    std::fs::write(&runner, "#!/usr/bin/env python3\n").expect("write runner");
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let argv = vec![runner.to_string_lossy().to_string()];
    match discover_from_argv(&argv).kind {
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        } => {}
        other => panic!("expected Source for shebang script, got {other:?}"),
    }
}

#[test]
fn inline_eval_is_not_parsed() {
    for argv in [
        vec!["python".into(), "-c".into(), "print(1)".into()],
        vec!["python3".into(), "--command".into(), "print(1)".into()],
        vec!["node".into(), "--eval".into(), "1".into()],
        vec!["node".into(), "-e".into(), "1".into()],
        vec!["node".into(), "-p".into(), "1".into()],
        vec!["node".into(), "--print".into(), "1".into()],
    ] {
        let d = discover_from_argv(&argv);
        assert!(
            matches!(d.kind, PayloadKind::InlineEval { .. }),
            "{argv:?} -> {:?}",
            d.kind
        );
        assert!(d.skips_native_elf());
    }
}

#[test]
fn delegating_launchers_are_flagged() {
    for argv0 in [
        "env",
        "/usr/bin/env",
        "env.exe",
        "py",
        "C:\\Windows\\py.exe",
        "pyw",
        "npx",
        "npx.EXE",
        "PY.eXe",
        "Env.ExE",
        // Exec wrappers
        "nice",
        "nohup",
        "timeout",
        "gtimeout",
        "setsid",
        "stdbuf",
        "chrt",
        "taskset",
        "ionice",
        "sudo",
        "doas",
        // Package runners
        "bunx",
        "uvx",
        "pipx",
        "pnpx",
        // Subcommand-based selection
        "uv",
        "poetry",
        "pipenv",
        "pdm",
        "hatch",
        "conda",
        "npm",
        "pnpm",
        "yarn",
        "deno",
        "bun",
        "docker",
        "podman",
    ] {
        assert!(
            delegating_launcher_reason(&CommandNames::new(argv0, None)).is_some(),
            "{argv0} must be flagged as a delegating launcher"
        );
    }
    for argv0 in ["python", "python3", "node", "server.py", "/bin/sh"] {
        assert!(
            delegating_launcher_reason(&CommandNames::new(argv0, None)).is_none(),
            "{argv0} is a direct interpreter or file, not a delegating launcher"
        );
    }
}

#[test]
fn env_launcher_marks_workload_not_fully_bound() {
    let argv = vec![
        "env".into(),
        "FOO=1".into(),
        "python3".into(),
        "server.py".into(),
    ];
    let discovery = discover_from_argv(&argv);
    let w = workload_hashes(&argv, &discovery);
    assert!(
        w.unbound_reasons.iter().any(|r| r.contains("env")),
        "env launch must carry a reason: {:?}",
        w.unbound_reasons
    );
    // The hash model cannot express a pin on the command env selects:
    // binary-hash targets the spawned argv[0] and entrypoint-hash must
    // match the executable or first payload argument.
    assert!(w.entrypoint.is_none());
}

#[test]
fn env_shebang_marks_direct_exec_unbound() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_envshebang_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("server.py");
    std::fs::write(&script, "#!/usr/bin/env python3\nprint(1)\n").unwrap();

    // Direct exec: argv[0] is the script — the kernel honors the shebang.
    let argv = vec![script.to_string_lossy().into_owned()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
        "{:?}",
        w.unbound_reasons
    );

    // Indirect exec (`python3 server.py`): the interpreter is pinned and
    // the shebang is inert — no caveat.
    let argv = vec!["python3".into(), script.to_string_lossy().into_owned()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        !w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
        "{:?}",
        w.unbound_reasons
    );

    // Fixed shebang (no env): no PATH delegation, but the kernel-selected
    // interpreter image is still not pinned — the draft flags it.
    std::fs::write(&script, "#!/usr/bin/python3\nprint(1)\n").unwrap();
    let argv = vec![script.to_string_lossy().into_owned()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        !w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
        "{:?}",
        w.unbound_reasons
    );
    assert!(
        w.unbound_reasons
            .iter()
            .any(|r| r.contains("shebang interpreter '/usr/bin/python3'")),
        "fixed shebang must flag the unpinned interpreter: {:?}",
        w.unbound_reasons
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn native_script_shebang_marks_unpinned_interpreter() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_native_shebang_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Extensionless + unrecognized interpreter (`sh`) → Native, but the
    // kernel still honors the shebang — the interpreter must be flagged.
    let script = dir.join("entrypoint");
    std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    let argv = vec![script.to_string_lossy().into_owned()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        w.binary.is_some(),
        "binary-hash pins the entry script itself: {w:?}"
    );
    assert!(
        w.unbound_reasons
            .iter()
            .any(|r| r.contains("shebang interpreter '/bin/sh'")),
        "{:?}",
        w.unbound_reasons
    );

    // An env shebang naming an unmodeled interpreter is flagged too.
    std::fs::write(&script, "#!/usr/bin/env bash\necho hi\n").unwrap();
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
        "{:?}",
        w.unbound_reasons
    );

    // No shebang → a plain file carries no kernel-selected interpreter —
    // no caveat.
    std::fs::write(&script, "echo hi\n").unwrap();
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        !w.unbound_reasons.iter().any(|r| r.contains("shebang")),
        "{:?}",
        w.unbound_reasons
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shebang_interpreter_parses_command_token() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_shebang_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Extensionless so only the shebang can identify the language.
    let script = dir.join("entrypoint");
    let kind_of = |body: &str| {
        std::fs::write(&script, body).unwrap();
        discover_from_path(&script).kind
    };

    // Fixed interpreter shebangs.
    assert_eq!(
        kind_of("#!/usr/bin/python3 -u\nprint(1)\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            path: script.clone(),
        }
    );
    assert_eq!(
        kind_of("#!/usr/bin/node\nconsole.log(1)\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            path: script.clone(),
        }
    );

    // env delegation: plain, -S with options, and VAR=val assignments.
    assert!(matches!(
        kind_of("#!/usr/bin/env python3\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));
    assert!(matches!(
        kind_of("#!/usr/bin/env -S python3 -u\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));
    assert!(matches!(
        kind_of("#!/usr/bin/env -S FOO=1 node --harmony\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            ..
        }
    ));
    assert!(matches!(
        kind_of("#!/usr/bin/env -i -u PATH node\n"),
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            ..
        }
    ));

    // Substrings in hook paths, options, or eval text must not classify.
    let hook = dir.join("python-hooks").join("run");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    assert_eq!(discover_from_path(&hook).kind, PayloadKind::Native);
    assert_eq!(
        kind_of("#!/usr/bin/env -S bash -c 'echo python'\n"),
        PayloadKind::Native
    );
    assert_eq!(kind_of("#!/opt/python-tools/run.sh\n"), PayloadKind::Native);
    assert_eq!(kind_of("#!/usr/bin/env -S deno run\n"), PayloadKind::Native);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shebang_line_uses_only_the_first_line() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_shebang_bytes_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("entrypoint");

    // Invalid UTF-8 after the shebang line must not hide it — a bundled
    // script can carry binary payloads past line one.
    std::fs::write(&script, b"#!/usr/bin/env python3\n\xff\xfebinary\xff").unwrap();
    assert!(matches!(
        discover_from_path(&script).kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));

    // CRLF endings lose the carriage return before token parsing.
    std::fs::write(&script, b"#!/usr/bin/env node\r\nconsole.log(1)\r\n").unwrap();
    assert!(matches!(
        discover_from_path(&script).kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Node,
            ..
        }
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extensionless_shebang_script_is_a_source_payload() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_extless_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // PATH-installed entry scripts (`mcp-server-git`, …) are commonly
    // extensionless with an env shebang.
    let script = dir.join("mcp-server");
    std::fs::write(&script, "#!/usr/bin/env python3\nprint(1)\n").unwrap();

    let argv = vec![script.to_string_lossy().into_owned()];
    let d = discover_from_argv(&argv);
    match &d.kind {
        PayloadKind::Source { interpreter, path } => {
            assert_eq!(*interpreter, InterpreterKind::Python);
            assert_eq!(
                path,
                &crate::workload::resolve_command_path(&argv[0]).unwrap()
            );
        }
        other => panic!("expected Source for shebang script, got {other:?}"),
    }

    // Direct exec: the env shebang's PATH-selected interpreter is unpinned.
    let w = workload_hashes(&argv, &d);
    assert!(
        w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
        "{:?}",
        w.unbound_reasons
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn option_operands_are_not_the_payload() {
    // Value-taking options consume the next token; pinning it would bind
    // a preload module or flag value while the real script stays unpinned.
    for (argv, expected) in [
        (
            vec![
                "node".into(),
                "--require".into(),
                "stub.cjs".into(),
                "index.js".into(),
            ],
            "index.js",
        ),
        (
            vec![
                "node".into(),
                "--preserve-symlinks".into(),
                "--loader".into(),
                "ts-loader.mjs".into(),
                "server.js".into(),
            ],
            "server.js",
        ),
        (
            vec![
                "python".into(),
                "-W".into(),
                "ignore".into(),
                "-X".into(),
                "utf8".into(),
                "server.py".into(),
            ],
            "server.py",
        ),
    ] {
        let d = discover_from_argv(&argv);
        match d.kind {
            PayloadKind::Source { path, .. } => {
                assert_eq!(path, PathBuf::from(expected), "{argv:?}")
            }
            other => panic!("expected Source for {argv:?}, got {other:?}"),
        }
    }
}

#[test]
fn inline_eval_reason_without_known_interpreter() {
    // `sh -c` / `perl -e` are Native for discovery, but the runtime
    // refuses the launch — the draft must carry the reason instead of
    // looking fully bound.
    for argv in [
        vec!["sh".into(), "-c".into(), "exec node server.js".into()],
        vec!["perl".into(), "-e".into(), "1".into()],
        vec!["ruby".into(), "-e".into(), "puts 1".into()],
    ] {
        let w = workload_hashes(&argv, &discover_from_argv(&argv));
        assert!(
            w.unbound_reasons
                .iter()
                .any(|r| r.contains("inline evaluation")),
            "{argv:?} -> {:?}",
            w.unbound_reasons
        );
        assert!(w.entrypoint.is_none());
    }
}

#[test]
fn unresolvable_payload_args_get_unbound_reason() {
    // `perl --unknown-option script.pl` is Native for discovery, but
    // the unknown long option makes the payload boundary ambiguous —
    // the draft still carries an unbound-entrypoint reason that names
    // the blocking option.
    let argv = vec!["perl".into(), "--unknown-option".into(), "script.pl".into()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        w.unbound_reasons
            .iter()
            .any(|r| r.contains("'--unknown-option'") && r.contains("ambiguous")),
        "{:?}",
        w.unbound_reasons
    );
    // Bare interpreter: no arguments, nothing to bind, no reason.
    let argv = vec!["perl".into()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        !w.unbound_reasons
            .iter()
            .any(|r| r.contains("payload cannot be identified")),
        "{:?}",
        w.unbound_reasons
    );
}

#[test]
fn module_flag_is_unresolved() {
    for argv in [
        vec!["python".into(), "-m".into(), "http.server".into()],
        vec!["python".into(), "-m".into()],
        vec!["node".into(), "-m".into(), "mod".into()],
    ] {
        let d = discover_from_argv(&argv);
        assert!(
            matches!(d.kind, PayloadKind::Unresolved { .. }),
            "{argv:?} -> {:?}",
            d.kind
        );
    }
    let d = discover_from_argv(&["python".into(), "-m".into(), "http.server".into()]);
    match d.kind {
        PayloadKind::Unresolved { reason } => {
            assert!(reason.contains("-m"), "{reason}")
        }
        other => panic!("expected Unresolved, got {other:?}"),
    }
    // The attached `-m<module>` spelling lands on the same reason —
    // `first_payload_arg_index` ends its scan at that token.
    let d = discover_from_argv(&["python".into(), "-mhttp.server".into(), "8080".into()]);
    match d.kind {
        PayloadKind::Unresolved { reason } => {
            assert!(reason.contains("-m"), "{reason}")
        }
        other => panic!("expected Unresolved, got {other:?}"),
    }
    // A live `-m` inside a cluster names the module on the next token
    // (`-Bm http.server`); `-Wm` is not a module flag — there `m` is
    // `-W`'s operand value.
    let d = discover_from_argv(&["python".into(), "-Bm".into(), "http.server".into()]);
    match d.kind {
        PayloadKind::Unresolved { reason } => {
            assert!(reason.contains("-m"), "{reason}")
        }
        other => panic!("expected Unresolved, got {other:?}"),
    }
    assert!(!crate::workload::python_cluster_names_module("-Wm"));
}

#[test]
fn discover_reports_ambiguous_payload_boundary() {
    // An unrecognized long option on a modeled family may consume the
    // script token — the reason names the option and the ambiguity.
    let d = discover_from_argv(&["node".into(), "--not-a-node-flag".into(), "srv.js".into()]);
    match d.kind {
        PayloadKind::Unresolved { reason } => {
            assert!(reason.contains("--not-a-node-flag"), "{reason}");
            assert!(reason.contains("ambiguous"), "{reason}");
        }
        other => panic!("expected Unresolved, got {other:?}"),
    }
    // No blocker named when there is simply no payload token.
    let d = discover_from_argv(&["node".into()]);
    match d.kind {
        PayloadKind::Unresolved { reason } => {
            assert!(reason.contains("no source payload"), "{reason}")
        }
        other => panic!("expected Unresolved, got {other:?}"),
    }
}

#[test]
fn payload_flag_after_script_is_not_inline_eval() {
    let argv = vec![
        "python".into(),
        "server.py".into(),
        "--command".into(),
        "payload".into(),
    ];
    assert!(!crate::workload::argv_contains_inline_eval(&argv));
    assert!(matches!(
        discover_from_argv(&argv).kind,
        PayloadKind::Source { .. }
    ));
}

#[test]
fn node_preload_flags_get_unbound_reason() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_preload_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("index.js");
    std::fs::write(&script, "console.log(1)\n").unwrap();

    for flag in ["--require", "-r"] {
        let argv = vec![
            "node".into(),
            flag.into(),
            "stub.cjs".into(),
            script.to_string_lossy().into_owned(),
        ];
        let w = workload_hashes(&argv, &discover_from_argv(&argv));
        assert!(
            w.unbound_reasons.iter().any(|r| r.contains("preload")),
            "{flag}: {:?}",
            w.unbound_reasons
        );
    }
    let argv = vec!["node".into(), script.to_string_lossy().into_owned()];
    let w = workload_hashes(&argv, &discover_from_argv(&argv));
    assert!(
        !w.unbound_reasons.iter().any(|r| r.contains("preload")),
        "{:?}",
        w.unbound_reasons
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn native_binary_stays_native() {
    let d = discover_from_argv(&["/usr/local/bin/mcp-native".into()]);
    assert_eq!(d.kind, PayloadKind::Native);
    assert!(!d.skips_native_elf());
}

#[test]
fn shebang_script_inspect() {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_shebang_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mcp-server");
    std::fs::write(&path, "#!/usr/bin/env python3\nprint(1)\n").unwrap();
    let d = discover_from_path(&path);
    assert!(matches!(
        d.kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn inspect_interpreter_binary_is_unresolved() {
    let d = discover_from_path(Path::new("/usr/bin/python3"));
    assert!(matches!(d.kind, PayloadKind::Unresolved { .. }));
    assert!(d.skips_native_elf());
}

#[test]
fn inspect_py_extension() {
    let d = discover_from_path(Path::new("tests/fixtures/py_mcp/fastmcp_literal.py"));
    assert!(matches!(
        d.kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));
    assert_eq!(
        native_skip_note(Path::new("server.py")),
        "native analysis skipped; source payload = server.py"
    );
}

#[test]
fn direct_script_argv0() {
    let d = discover_from_argv(&["./server.py".into()]);
    assert!(matches!(
        d.kind,
        PayloadKind::Source {
            interpreter: InterpreterKind::Python,
            ..
        }
    ));
}
