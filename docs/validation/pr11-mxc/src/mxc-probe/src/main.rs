use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;

use mxc_sdk::v1::configs::{
    CaptureDenials, CaptureDenialsMode, ProcessContainerConfig,
};
use mxc_sdk::v1::{
    self, ContainerRequest, Containment, FilesystemPolicy, NetworkAction,
    NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy,
    NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
    WaitResult,
};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "support".into());
    match mode.as_str() {
        "support" => support(),
        "run" | "spawn" => launch(&mode),
        "proxy" => mini_proxy(),
        other => eprintln!("unknown mode {other}"),
    }
}

fn support() {
    let s = v1::platform_support();
    println!("is_supported={}", s.is_supported);
    println!("reason={:?}", s.reason);
    println!("available_methods={:?}", s.available_methods);
    println!("bubblewrap_network={:?}", s.bubblewrap_network);
    for b in v1::available_backends() {
        println!("backend={b:?}");
    }
}

// Minimal HTTP/CONNECT forward proxy for observing proxy-mode traffic.
fn mini_proxy() {
    let l = TcpListener::bind("127.0.0.1:59199").unwrap();
    eprintln!("proxy on 59199");
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let mut rdr = BufReader::new(match s.try_clone() {
                Ok(c) => c,
                Err(_) => return,
            });
            let mut line = String::new();
            if rdr.read_line(&mut line).is_err() {
                return;
            }
            eprintln!("PROXY-REQ>> {}", line.trim());
            // drain headers
            loop {
                let mut h = String::new();
                if rdr.read_line(&mut h).is_err() || h.trim().is_empty() {
                    break;
                }
            }
            let target = if let Some(rest) = line.strip_prefix("CONNECT ") {
                rest.split_whitespace().next().unwrap_or("")
            } else {
                ""
            };
            if target.is_empty() {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nPROXY-OK\n");
                return;
            }
            match std::net::TcpStream::connect(target) {
                Ok(up) => {
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    let mut a = match s.try_clone() { Ok(c) => c, Err(_) => return };
                    let mut b = match up.try_clone() { Ok(c) => c, Err(_) => return };
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut b, &mut a);
                    });
                    let mut r = s;
                    let mut w = up;
                    let _ = std::io::copy(&mut r, &mut w);
                }
                Err(e) => {
                    eprintln!("PROXY-UPSTREAM-FAIL {target} {e}");
                    let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                }
            }
        });
    }
}

fn launch(mode: &str) {
    let root = std::env::temp_dir().join("mxc-probe").join("work");
    let ro = root.join("ro");
    let rw = root.join("rw");
    let deny = root.join("deny");
    let ungranted = root.join("ungranted");
    for d in [&ro, &rw, &deny, &ungranted, &root.join("capture")] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(ro.join("ro-read.txt"), "ro-content").unwrap();
    std::fs::write(deny.join("deny-read.txt"), "deny-content").unwrap();
    std::fs::write(ungranted.join("ungranted.txt"), "ungranted-content").unwrap();

    let probe = std::env::var("MXC_PROBE_EXE")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("winiso_probe.exe")))
                .filter(|p| p.exists())
        })
        .unwrap_or_else(|| {
            eprintln!("winiso_probe binary not found — set MXC_PROBE_EXE or place winiso_probe.exe next to this driver");
            std::process::exit(1);
        });
    let bind = std::env::var("MXC_PROBE_BIND").unwrap_or_else(|_| "127.0.0.1:0".into());
    let listener = TcpListener::bind(&bind).unwrap();
    let allow_port = listener.local_addr().unwrap().port();
    let allow_addr = std::env::var("MXC_PROBE_ALLOW_ADDR")
        .unwrap_or_else(|_| format!("127.0.0.1:{allow_port}"));
    let deny_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let deny_port = deny_listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
        }
    });
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = deny_listener.accept() {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
        }
    });

    let deny_addr = std::env::var("MXC_PROBE_DENY_ADDR")
        .unwrap_or_else(|_| format!("127.0.0.1:{deny_port}"));
    let command = if let Ok(c) = std::env::var("MXC_PROBE_COMMAND") {
        c
    } else {
        format!(
            "\"{}\" attempts --ro \"{}\" --rw \"{}\" --deny \"{}\" --ungranted \"{}\" --net-allow {} --net-deny {}",
            probe.display(),
            ro.display(),
            rw.display(),
            deny.display(),
            ungranted.display(),
            allow_addr,
            deny_addr,
        )
    };

    let system_root = std::env::var("SystemRoot").unwrap();
    let containment = if std::env::var_os("MXC_PROBE_ISO").is_some() {
        Containment::IsolationSession
    } else if std::env::var_os("MXC_PROBE_CAPTURE").is_some() {
        let mut cap = CaptureDenials::default();
        cap.mode = if std::env::var_os("MXC_PROBE_CAPTURE_ALLOW").is_some() {
            CaptureDenialsMode::Allow
        } else {
            CaptureDenialsMode::Block
        };
        cap.output_path = Some(root.display().to_string() + "\\capture\\denials.json");
        let mut cfg = ProcessContainerConfig::default();
        cfg.capture_denials = Some(cap);
        Containment::ProcessContainer(cfg)
    } else {
        Containment::Process
    };
    let request = ContainerRequest {
        containment,
        filesystem: if std::env::var_os("MXC_PROBE_NO_FS").is_some() { None } else { Some(FilesystemPolicy {
            readonly_paths: {
                let mut v = vec![
                    ro.display().to_string(),
                    probe.parent().unwrap().display().to_string(),
                    std::env::var("SystemRoot").unwrap(),
                ];
                if let Ok(x) = std::env::var("MXC_PROBE_EXTRA_RO") {
                    v.push(x);
                }
                v
            },
            readwrite_paths: vec![rw.display().to_string()],
            denied_paths: vec![deny.display().to_string()],
            ..Default::default()
        })},
        network: if std::env::var_os("MXC_PROBE_NO_NET").is_some() { None } else { Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(if std::env::var_os("MXC_PROBE_ISO").is_some()
                    || std::env::var_os("MXC_PROBE_EGRESS_ALLOW_ALL").is_some()
                {
                    NetworkAction::Allow
                } else {
                    NetworkAction::Deny
                }),
                allow: if std::env::var_os("MXC_PROBE_PROXY").is_some()
                    || std::env::var_os("MXC_PROBE_ISO").is_some()
                {
                    None
                } else {
                    Some(vec![NetworkRulePolicy {
                    to: Some(vec![NetworkPeerPolicy {
                        cidr: std::env::var("MXC_PROBE_ALLOW_CIDR")
                            .unwrap_or_else(|_| "127.0.0.1/32".into()),
                        except: std::env::var("MXC_PROBE_ALLOW_EXCEPT").ok().map(|e| vec![e]),
                    }]),
                    ports: if std::env::var_os("MXC_PROBE_ALLOW_NOPORT").is_some() {
                        None
                    } else {
                        Some(vec![NetworkPortPolicy {
                            protocol: Some(NetworkProtocol::Tcp),
                            port: Some(allow_port),
                            end_port: None,
                        }])
                    },
                    }])
                },
                deny: if let Ok(c) = std::env::var("MXC_PROBE_DENY_CIDR") {
                    Some(vec![NetworkRulePolicy {
                        to: Some(vec![NetworkPeerPolicy {
                            cidr: c,
                            except: None,
                        }]),
                        ports: None,
                    }])
                } else if std::env::var_os("MXC_PROBE_DENY_UDP").is_some() {
                    Some(vec![NetworkRulePolicy {
                        to: Some(vec![NetworkPeerPolicy {
                            cidr: "0.0.0.0/0".into(),
                            except: None,
                        }]),
                        ports: Some(vec![NetworkPortPolicy {
                            protocol: Some(NetworkProtocol::Udp),
                            port: Some(1),
                            end_port: Some(65535),
                        }]),
                    }])
                } else {
                    None
                },
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(if std::env::var_os("MXC_PROBE_PROXY").is_some()
                    || std::env::var_os("MXC_PROBE_ISO").is_some()
                {
                    NetworkAction::Allow
                } else {
                    NetworkAction::Deny
                }),
                host_loopback: Some(if std::env::var_os("MXC_PROBE_NO_LB").is_some() {
                    NetworkAction::Deny
                } else {
                    NetworkAction::Allow
                }),
            }),
            runtime_config: if let Ok(p) = std::env::var("MXC_PROBE_PROXY") {
                Some(NetworkRuntimeConfig {
                    network_proxy: Some(p),
                })
            } else {
                None
            },
        })},
        ui: if std::env::var_os("MXC_PROBE_UI").is_some() {
            Some(mxc_sdk::v1::UiPolicy {
                disable: false,
                ..Default::default()
            })
        } else {
            None
        },
        working_directory: if std::env::var_os("MXC_PROBE_NO_WD").is_some() {
            None
        } else {
            Some(rw.display().to_string())
        },
        environment: if std::env::var_os("MXC_PROBE_DEFAULT_ENV").is_some() {
            None
        } else {
            Some(vec![
                ("SystemRoot".into(), system_root),
                ("LOCALAPPDATA".into(), rw.display().to_string()),
                ("TEMP".into(), rw.display().to_string()),
                ("TMP".into(), rw.display().to_string()),
                ("PATH".into(), format!("{}\\System32", std::env::var("SystemRoot").unwrap())),
                ("winDir".into(), std::env::var("SystemRoot").unwrap()),
                ("WINISO_PROBE_MARKER".into(), "delivered".into()),
                ("WINISO_RO_DIR".into(), ro.display().to_string()),
            ])
        },
        timeout_ms: std::env::var("MXC_PROBE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .or(Some(30_000)),
        ..ContainerRequest::new(command)
    };

    if mode == "run" {
        let t0 = std::time::Instant::now();
        match v1::run(request, Default::default()) {
            Ok(r) => {
                println!("outcome={:?}", r.outcome);
                println!("metadata={:?}", r.output_metadata);
                println!("stdout<<{}", String::from_utf8_lossy(&r.stdout));
                println!("stderr<<{}", String::from_utf8_lossy(&r.stderr));
                for w in &r.warnings {
                    println!("warning: {w}");
                }
            }
            Err(e) => {
                println!("run error: {e}");
                if let Some(rem) = &e.remediation {
                    println!("remediation: {rem}");
                }
            }
        }
        println!("elapsed_ms={}", t0.elapsed().as_millis());
        return;
    }

    // spawn leg: live stdio pipes + wait
    match v1::spawn(request, Default::default()) {
        Ok(mut p) => {
            println!("id={} warnings={:?}", p.id(), p.warnings());
            println!("take_stdin={}", p.take_stdin().is_some());
            println!("take_native_stdio={:?}", p.take_native_stdio().map(|o| o.is_some()));
            let mut out = String::new();
            if let Some(mut so) = p.take_stdout() {
                let mut buf = Vec::new();
                let _ = so.read_to_end(&mut buf);
                out = String::from_utf8_lossy(&buf).into_owned();
            }
            let w = p.wait();
            println!("wait={:?}", w);
            println!("spawned stdout<<{out}");
            match w {
                Ok(WaitResult::Exited(c)) => println!("exit={c}"),
                other => println!("wait-other={other:?}"),
            }
        }
        Err(e) => {
            println!("spawn error: {e}");
            if let Some(rem) = &e.remediation {
                println!("remediation: {rem}");
            }
        }
    }
}
