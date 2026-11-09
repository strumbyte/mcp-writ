//! Modes `psec-run` / `psec-spec-test` — the PSEC (BaseContainer)
//! candidate: hand-built FlatBuffers spec → CreateProcessSecurityEnvironment
//! → child spawned with PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT.

use std::ffi::c_void;
use std::path::PathBuf;

use crate::ffi::*;
use crate::helpers::*;
use crate::psec_spec::*;
use crate::spawn::*;

pub(crate) fn mode_psec_run(args: &[String]) -> String {
    unsafe {
        // Grant flags end at `--image` — the image tail is the child's
        // own argv, never re-parsed for --ro/--rw/--deny-shaped args.
        let run_args = args_before_image(args);
        let mut ro: Vec<String> = Vec::new();
        let mut rw: Vec<String> = Vec::new();
        let mut deny: Vec<String> = Vec::new();
        // `--net-cidr addr/prefix:port` emits an AllowCidr rule; the
        // `--net-*-dest` args pick which endpoints the child probes.
        let mut net_cidr: Option<(String, u8, u16)> = None;
        let mut net_allow_dest: Option<String> = None;
        let mut net_deny_dest: Option<String> = None;
        let mut spec_minor: u16 = 0;
        let mut net_excepts: Vec<(String, u8)> = Vec::new();
        let mut net_deny_rules: Vec<(String, u8, u16)> = Vec::new();
        let mut spec_caps: Option<String> = None;
        let mut enumerate: Vec<String> = Vec::new();
        let mut ingress: Option<(u8, u8)> = None;
        let mut bad_arg: Option<String> = None;
        let mut i = 0;
        while i < run_args.len() {
            match run_args[i].as_str() {
                "--ro" => {
                    if let Some(v) = run_args.get(i + 1) {
                        ro.push(v.clone());
                    }
                    i += 2;
                }
                "--rw" => {
                    if let Some(v) = run_args.get(i + 1) {
                        rw.push(v.clone());
                    }
                    i += 2;
                }
                "--deny" => {
                    if let Some(v) = run_args.get(i + 1) {
                        deny.push(v.clone());
                    }
                    i += 2;
                }
                "--net-cidr" => {
                    let ok = run_args.get(i + 1).is_some_and(|v| {
                        // "a.b.c.d/prefix:port" or "v6/prefix:port".
                        if let Some((net, port)) = v.rsplit_once(':') {
                            if let Some((addr, prefix)) = net.rsplit_once('/') {
                                if let (Ok(pfx), Ok(pt)) =
                                    (prefix.parse::<u8>(), port.parse::<u16>())
                                {
                                    net_cidr = Some((addr.to_string(), pfx, pt));
                                    return true;
                                }
                            }
                        }
                        false
                    });
                    if !ok {
                        bad_arg = Some("--net-cidr".into());
                    }
                    i += 2;
                }
                "--net-allow-dest" => {
                    if let Some(v) = run_args.get(i + 1) {
                        net_allow_dest = Some(v.clone());
                    }
                    i += 2;
                }
                "--net-deny-dest" => {
                    if let Some(v) = run_args.get(i + 1) {
                        net_deny_dest = Some(v.clone());
                    }
                    i += 2;
                }
                "--spec-minor" => {
                    if !run_args
                        .get(i + 1)
                        .is_some_and(|v| v.parse::<u16>().map(|m| spec_minor = m).is_ok())
                    {
                        bad_arg = Some("--spec-minor".into());
                    }
                    i += 2;
                }
                "--net-except" => {
                    // "a.b.c.d/prefix" — except subnet on the allow rule.
                    let ok = run_args.get(i + 1).is_some_and(|v| {
                        if let Some((a, p)) = v.rsplit_once('/') {
                            if let Ok(pf) = p.parse::<u8>() {
                                net_excepts.push((a.to_string(), pf));
                                return true;
                            }
                        }
                        false
                    });
                    if !ok {
                        bad_arg = Some("--net-except".into());
                    }
                    i += 2;
                }
                "--net-deny-cidr" => {
                    // "a.b.c.d/prefix:port" — egress deny endpoint rule.
                    let ok = run_args.get(i + 1).is_some_and(|v| {
                        if let Some((net, port)) = v.rsplit_once(':') {
                            if let Some((a, p)) = net.rsplit_once('/') {
                                if let (Ok(pf), Ok(pt)) =
                                    (p.parse::<u8>(), port.parse::<u16>())
                                {
                                    net_deny_rules.push((a.to_string(), pf, pt));
                                    return true;
                                }
                            }
                        }
                        false
                    });
                    if !ok {
                        bad_arg = Some("--net-deny-cidr".into());
                    }
                    i += 2;
                }
                "--spec-caps" => {
                    if let Some(v) = run_args.get(i + 1) {
                        spec_caps = Some(v.clone());
                    }
                    i += 2;
                }
                "--enumerate" => {
                    if let Some(v) = run_args.get(i + 1) {
                        enumerate.push(v.clone());
                    }
                    i += 2;
                }
                "--ingress" => {
                    // "default,host_loopback" as u8 pair.
                    let ok = run_args.get(i + 1).is_some_and(|v| {
                        if let Some((a, b)) = v.split_once(',') {
                            if let (Ok(d), Ok(h)) =
                                (a.parse::<u8>(), b.parse::<u8>())
                            {
                                ingress = Some((d, h));
                                return true;
                            }
                        }
                        false
                    });
                    if !ok {
                        bad_arg = Some("--ingress".into());
                    }
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if let Some(a) = &bad_arg {
            return format!(
                "{{\"mode\":\"psec-run\",\"error\":\"bad-arg\",\"arg\":{}}}",
                js(a)
            );
        }
        // Bind the allow-leg listener first so its port can be pinned in
        // the spec's egress rule — the allow/deny contrast then proves
        // destination+port granularity, not just "deny-all".
        let listener = bind_loopback();
        let allow_port = listener
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port());
        let net_spec = match (&net_cidr, allow_port) {
            (Some((addr, prefix, port)), _) => NetSpec::AllowCidr {
                addr: addr.clone(),
                prefix: *prefix,
                port: *port,
                end_port: 0,
            },
            (None, Some(p)) => NetSpec::AllowOnly {
                addr: "127.0.0.1".into(),
                port: p,
            },
            (None, None) => NetSpec::DenyAll,
        };
        let spec = psec_spec_full(
            &ro,
            &rw,
            &deny,
            &enumerate,
            &net_spec,
            &net_excepts,
            &net_deny_rules,
            spec_caps.as_deref(),
            ingress,
            true,
            spec_minor,
        );
        // Spec self-check: magic + non-trivial size recorded for evidence.
        let spec_ok = spec.len() >= 16 && &spec[4..8] == b"PSEC";

        let dll = load_system_dll("processmodel.dll");
        if dll.is_null() {
            return format!(
                "{{\"mode\":\"psec-run\",\"spec_len\":{},\"spec_ok\":{},\"create_hr\":\"unavailable\"}}",
                spec.len(),
                spec_ok
            );
        }
        let cp = export_addr(dll, "CreateProcessSecurityEnvironment");
        let clp = export_addr(dll, "CloseProcessSecurityEnvironment");
        if cp.is_null() || clp.is_null() {
            return format!(
                "{{\"mode\":\"psec-run\",\"spec_len\":{},\"spec_ok\":{},\"create_hr\":\"exports-missing\"}}",
                spec.len(),
                spec_ok
            );
        }
        let create: unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> HRESULT =
            std::mem::transmute(cp);
        let close: unsafe extern "system" fn(HANDLE) = std::mem::transmute(clp);
        let mut env: HANDLE = std::ptr::null_mut();
        let hr = create(
            spec.as_ptr() as *const c_void,
            spec.len() as u32,
            0,
            &mut env,
        );
        if hr != 0 || env.is_null() {
            return format!(
                "{{\"mode\":\"psec-run\",\"spec_len\":{},\"spec_ok\":{},\"create_hr\":\"{}\"}}",
                spec.len(),
                spec_ok,
                hr_str(hr)
            );
        }

        // Attributes: the security-environment handle; spawn_wrapped
        // adds the handle list itself.
        let attrs: [(usize, *const c_void, usize); 1] = [(
            PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
            &env as *const _ as *const c_void,
            std::mem::size_of::<usize>(),
        )];
        // Same story as ac-run: pass context on argv (env may not reach a
        // security-environment child) and drop a spawnable exe copy into
        // the RW dir for the grandchild leg. `--image` spawns an external
        // binary instead — the Node/Python launch-condition leg.
        let (image, image_argv) = split_image(args);
        let mut gc_exe_arg: Option<PathBuf> = None;
        if image.is_none() {
            if let Some(rwdir) = rw.first() {
                let exe = std::env::current_exe().unwrap();
                let copy = PathBuf::from(rwdir).join("mcp-writ-pr30-child.exe");
                if std::fs::copy(&exe, &copy).is_ok() {
                    gc_exe_arg = Some(copy);
                }
            }
        }
        let mut child_args = vec!["attempts".to_string()];
        for v in &ro {
            child_args.push("--ro".into());
            child_args.push(v.clone());
        }
        for v in &rw {
            child_args.push("--rw".into());
            child_args.push(v.clone());
        }
        for v in &deny {
            child_args.push("--deny".into());
            child_args.push(v.clone());
        }
        for v in &enumerate {
            child_args.push("--enum".into());
            child_args.push(v.clone());
        }
        for (env_var, flag) in [
            ("WINISO_UNGRANTED_DIR", "--ungranted"),
            ("WINISO_NET_ADDR", "--net-deny"),
        ] {
            if let Ok(v) = std::env::var(env_var) {
                child_args.push(flag.into());
                child_args.push(v);
            }
        }
        // The listener fallback + pinned-port deny leg exist only when
        // the spec actually carries the listener rule (AllowOnly — i.e.
        // net_cidr unset and the listener bound).
        let listener_rule = matches!(&net_spec, NetSpec::AllowOnly { .. });
        if let Some(d) = &net_allow_dest {
            child_args.push("--net-allow".into());
            child_args.push(d.clone());
        } else if listener_rule
            && let Some((_, addr)) = &listener
        {
            child_args.push("--net-allow".into());
            child_args.push(addr.clone());
        }
        if let Some(d) = &net_deny_dest {
            child_args.push("--net-deny".into());
            child_args.push(d.clone());
        }
        if listener_rule
            && let Some(p) = allow_port
        {
            // Same pinned port on a non-local destination — isolates the
            // destination rule from the port rule.
            child_args.push("--net-deny2".into());
            child_args.push(format!("10.255.255.1:{p}"));
        }
        child_args.push("--gc-sleep".into());
        child_args.push("20000".into());
        if let Some(gc) = &gc_exe_arg {
            child_args.push("--gc-exe".into());
            child_args.push(gc.to_string_lossy().into_owned());
        }
        let child_args = if image.is_some() { image_argv } else { child_args };
        let spawn_image = image.clone().unwrap_or_else(|| std::env::current_exe().unwrap());
        let spawn = spawn_wrapped(&spawn_image, &child_args, &attrs);
        drop(listener);
        close(env);
        FreeLibrary(dll);
        let child_json = child_json_or_null(&spawn.child_json);
        let net_label = match &net_spec {
            NetSpec::AllowCidr { .. } => "allow-cidr",
            NetSpec::AllowOnly { .. } => "allow-listener",
            NetSpec::DenyAll => "deny-all",
            _ => "other",
        };
        format!(
            "{{\"mode\":\"psec-run\",\"net\":{},\"spec_len\":{},\"spec_ok\":{},\"create_hr\":\"{}\",\"env_closed\":true,\"child_image\":{},\"spawn_ok\":{},\"spawn_detail\":{},\"child_pid\":{},\"gc_pid\":{},\"gc_killed\":{},\"child\":{}{}}}",
            js(net_label),
            spec.len(),
            spec_ok,
            hr_str(hr),
            image
                .as_ref()
                .map(|p| js(&p.to_string_lossy()))
                .unwrap_or_else(|| "null".into()),
            spawn.ok,
            js(&spawn.detail),
            spawn.child_pid,
            spawn.gc_pid.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            spawn.gc_killed.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            child_json,
            child_stdout_field(&spawn.child_json)
        )
    }
}

pub(crate) fn mode_psec_spec_test() -> String {
    unsafe {
        let dll = load_system_dll("processmodel.dll");
        if dll.is_null() {
            return "{\"mode\":\"psec-spec-test\",\"dll_loaded\":false}".into();
        }
        let cp = export_addr(dll, "CreateProcessSecurityEnvironment");
        let clp = export_addr(dll, "CloseProcessSecurityEnvironment");
        if cp.is_null() || clp.is_null() {
            FreeLibrary(dll);
            return "{\"mode\":\"psec-spec-test\",\"dll_loaded\":true,\"exports\":false}".into();
        }
        let create: unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> HRESULT =
            std::mem::transmute(cp);
        let close: unsafe extern "system" fn(HANDLE) = std::mem::transmute(clp);
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let dir = format!("{sys_root}\\System32");
        let cdir = "C:\\".to_string();
        let variants: Vec<(&str, Vec<u8>)> = vec![
            ("minimal-ident-v1.0", psec_spec_minimal(true, 0)),
            ("minimal-ident-v1.1", psec_spec_minimal(true, 1)),
            ("minimal-noident", psec_spec_minimal(false, 0)),
            (
                "deny-only",
                psec_spec(&[], &[], std::slice::from_ref(&dir), &NetSpec::None, true),
            ),
            (
                "ro-only",
                psec_spec(std::slice::from_ref(&dir), &[], &[], &NetSpec::None, true),
            ),
            (
                "rw-only",
                psec_spec(&[], std::slice::from_ref(&dir), &[], &NetSpec::None, true),
            ),
            (
                "net-only",
                psec_spec(&[], &[], &[], &NetSpec::DenyAll, true),
            ),
            (
                "net-allow-rule",
                psec_spec(
                    &[],
                    &[],
                    &[],
                    &NetSpec::AllowOnly {
                        addr: "127.0.0.1".into(),
                        port: 443,
                    },
                    true,
                ),
            ),
            (
                "net-allow-cidr24",
                psec_spec(
                    &[],
                    &[],
                    &[],
                    &NetSpec::AllowCidr {
                        addr: "10.20.30.0".into(),
                        prefix: 24,
                        port: 443,
                        end_port: 0,
                    },
                    true,
                ),
            ),
            (
                "net-allow-v6",
                psec_spec(
                    &[],
                    &[],
                    &[],
                    &NetSpec::AllowCidr {
                        addr: "fd00::1".into(),
                        prefix: 128,
                        port: 443,
                        end_port: 0,
                    },
                    true,
                ),
            ),
            (
                "net-allow-portrange",
                psec_spec(
                    &[],
                    &[],
                    &[],
                    &NetSpec::AllowCidr {
                        addr: "10.20.30.40".into(),
                        prefix: 32,
                        port: 8000,
                        end_port: 8100,
                    },
                    true,
                ),
            ),
            (
                "net-allow-cidr24-v11",
                psec_spec_minor(
                    &[],
                    &[],
                    &[],
                    &NetSpec::AllowCidr {
                        addr: "10.20.30.0".into(),
                        prefix: 24,
                        port: 443,
                        end_port: 0,
                    },
                    true,
                    1,
                ),
            ),
            (
                "net-ingress-v11",
                psec_spec_minor(
                    &[],
                    &[],
                    &[],
                    &NetSpec::DenyAllIngress {
                        default_action: 0,
                        host_loopback: 1,
                    },
                    true,
                    1,
                ),
            ),
            (
                "fs-all-no-net",
                psec_spec(
                    std::slice::from_ref(&dir),
                    std::slice::from_ref(&dir),
                    std::slice::from_ref(&dir),
                    &NetSpec::None,
                    true,
                ),
            ),
            (
                "deny-nested",
                psec_spec(
                    &[],
                    &[],
                    &[format!("{dir}\\kernel32.dll")],
                    &NetSpec::None,
                    true,
                ),
            ),
            (
                "deny-cdrive",
                psec_spec(&[], &[], std::slice::from_ref(&cdir), &NetSpec::None, true),
            ),
            (
                "full-ident",
                psec_spec(
                    std::slice::from_ref(&dir),
                    std::slice::from_ref(&dir),
                    std::slice::from_ref(&dir),
                    &NetSpec::DenyAll,
                    true,
                ),
            ),
        ];
        let variants: Vec<(&str, Vec<u8>)> = variants
            .into_iter()
            .chain(psec_spec_v11_extras())
            .collect();
        let mut out = String::from("{\"mode\":\"psec-spec-test\",\"attempts\":[");
        for (i, (label, spec)) in variants.iter().enumerate() {
            let mut env: HANDLE = std::ptr::null_mut();
            let hr = create(
                spec.as_ptr() as *const c_void,
                spec.len() as u32,
                0,
                &mut env,
            );
            let closed = if !env.is_null() {
                close(env);
                true
            } else {
                false
            };
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"variant\":{},\"len\":{},\"hr\":\"{}\",\"env_created\":{},\"closed\":{}}}",
                js(label),
                spec.len(),
                hr_str(hr),
                !env.is_null(),
                closed
            ));
        }
        out.push_str("]}");
        FreeLibrary(dll);
        out
    }
}
