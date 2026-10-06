//! Mode `attempts` — the measured-attempt battery, run in whatever
//! context executes the probe (host, AppContainer child, PSEC child).
//! Denials are the data: each attempt records what the OS actually did.

use std::path::PathBuf;

use crate::ffi::*;
use crate::helpers::*;

fn attempt(op: &str, target: &str, result: &str, detail: &str) -> String {
    format!(
        "{{\"op\":{},\"target\":{},\"result\":{},\"detail\":{}}}",
        js(op),
        js(target),
        js(result),
        js(detail)
    )
}

fn try_read_file(path: &PathBuf) -> (String, String) {
    match std::fs::read(path) {
        Ok(b) => ("ok".into(), format!("{} bytes", b.len())),
        Err(e) => (
            format!("err:{}", e.raw_os_error().unwrap_or(-1)),
            e.to_string(),
        ),
    }
}

fn try_write_file(path: &PathBuf) -> (String, String) {
    match std::fs::write(path, b"pr30-probe\n") {
        Ok(()) => ("ok".into(), "written".into()),
        Err(e) => (
            format!("err:{}", e.raw_os_error().unwrap_or(-1)),
            e.to_string(),
        ),
    }
}

/// `attempts` accepts the context dirs via `--ro/--rw/--deny/
/// --ungranted/--net/--gc-exe/--gc-sleep` argv *or* the WINISO_* env
/// vars — argv matters because a security-environment child may not
/// inherit the parent's environment block at all (itself recorded as
/// `env_seen` below).
pub(crate) fn mode_attempts(args: &[String]) -> String {
    let mut items: Vec<String> = Vec::new();
    let arg = |name: &str| -> Option<String> {
        let mut i = 0;
        while i < args.len() {
            if args[i] == name {
                return args.get(i + 1).cloned();
            }
            i += 1;
        }
        None
    };
    let env_vars: Vec<String> = [
        "WINISO_RO_DIR",
        "WINISO_RW_DIR",
        "WINISO_DENY_DIR",
        "WINISO_UNGRANTED_DIR",
        "WINISO_NET_ADDR",
        "WINISO_NET_ALLOW",
        "WINISO_SPAWN_GC",
        "WINISO_GC_EXE",
    ]
    .iter()
    .map(|k| {
        format!(
            "{{\"name\":{},\"seen\":{}}}",
            js(k),
            std::env::var(k).is_ok()
        )
    })
    .collect();
    let env = |k: &str, flag: &str| {
        arg(flag)
            .map(PathBuf::from)
            .or_else(|| std::env::var(k).ok().map(PathBuf::from))
    };

    // FS: read inside a RO grant.
    if let Some(dir) = env("WINISO_RO_DIR", "--ro") {
        let f = dir.join("ro-read.txt");
        let (r, d) = try_read_file(&f);
        items.push(attempt("fs_read_ro", &f.to_string_lossy(), &r, &d));
        let w = dir.join("pr30-write.txt");
        let (r, d) = try_write_file(&w);
        if r == "ok" {
            let _ = std::fs::remove_file(&w);
        }
        items.push(attempt("fs_write_ro", &w.to_string_lossy(), &r, &d));
    }
    // FS: write inside a RW grant.
    if let Some(dir) = env("WINISO_RW_DIR", "--rw") {
        let w = dir.join("pr30-write.txt");
        let (r, d) = try_write_file(&w);
        if r == "ok" {
            let _ = std::fs::remove_file(&w);
        }
        items.push(attempt("fs_write_rw", &w.to_string_lossy(), &r, &d));
    }
    // FS: read inside an explicit deny path (PSEC fs_deny) / ungranted dir
    // (AppContainer: no grant => deny either way).
    if let Some(dir) = env("WINISO_DENY_DIR", "--deny") {
        let f = dir.join("deny-read.txt");
        let (r, d) = try_read_file(&f);
        items.push(attempt("fs_read_deny", &f.to_string_lossy(), &r, &d));
        let w = dir.join("pr30-write.txt");
        let (r, d) = try_write_file(&w);
        if r == "ok" {
            let _ = std::fs::remove_file(&w);
        }
        items.push(attempt("fs_write_deny", &w.to_string_lossy(), &r, &d));
    }
    // FS: a dir granted to nobody.
    if let Some(dir) = env("WINISO_UNGRANTED_DIR", "--ungranted") {
        let f = dir.join("ungranted.txt");
        let (r, d) = try_read_file(&f);
        items.push(attempt("fs_read_ungranted", &f.to_string_lossy(), &r, &d));
    }
    // Enumerate: list a granted dir.
    if let Some(dir) = env("WINISO_RO_DIR", "--ro") {
        let (r, d) = match std::fs::read_dir(&dir) {
            Ok(rd) => (
                "ok".into(),
                format!("{} entries", rd.filter_map(|e| e.ok()).count()),
            ),
            Err(e) => (
                format!("err:{}", e.raw_os_error().unwrap_or(-1)),
                e.to_string(),
            ),
        };
        items.push(attempt("fs_enumerate_ro", &dir.to_string_lossy(), &r, &d));
    }
    // Network legs — three distinguishable targets:
    //   net_connect_allow    endpoint the policy is expected to allow
    //   net_connect_deny     same host, different port (port granularity)
    //   net_connect_deny2    different host entirely (destination rule)
    // The WSA codes are the evidence: WSAEACCES(10013) = policy deny,
    // WSAECONNREFUSED(10061) = network reached, timeout = filtered, a
    // WSAStartup failure = provider init blocked (LPAC).
    let net_wsastartup = unsafe {
        let mut wsa = [0u8; 400];
        let r = WSAStartup(0x0202, wsa.as_mut_ptr());
        if r == 0 {
            WSACleanup();
            ("ok".to_string(), "wsastartup".to_string())
        } else {
            (format!("err:{r}"), format!("WSAStartup -> {r}"))
        }
    };
    items.push(attempt(
        "net_wsastartup",
        "ws2_32",
        &net_wsastartup.0,
        &net_wsastartup.1,
    ));
    let mut net_leg = |op: &str, addr: String| {
        let (r, d) = raw_tcp_connect(&addr);
        items.push(attempt(op, &addr, &r, &d));
    };
    if let Some(addr) = arg("--net-allow").or_else(|| std::env::var("WINISO_NET_ALLOW").ok()) {
        net_leg("net_connect_allow", addr);
    }
    if let Some(addr) = arg("--net-deny").or_else(|| std::env::var("WINISO_NET_ADDR").ok()) {
        net_leg("net_connect_deny", addr);
    }
    if let Some(addr) = arg("--net-deny2") {
        net_leg("net_connect_deny_dest", addr);
    }
    // Registry: HKLM write must fail in any sandbox; record either way.
    unsafe {
        let sub = wide(r"SOFTWARE\mcp-writ-pr30-probe");
        let mut key: HKEY = std::ptr::null_mut();
        let mut disp = 0u32;
        // KEY_WRITE (0x20006) | KEY_READ (0x20019): create+set+read rights.
        let rc = RegCreateKeyExW(
            HKLM,
            sub.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_READ | 0x0002_0006,
            std::ptr::null_mut(),
            &mut key,
            &mut disp,
        );
        if rc == ERROR_SUCCESS {
            RegCloseKey(key);
            let _ = RegDeleteKeyW(HKLM, sub.as_ptr());
            items.push(attempt(
                "reg_write_hklm",
                "HKLM\\SOFTWARE\\mcp-writ-pr30-probe",
                "ok",
                "created+deleted",
            ));
        } else {
            items.push(attempt(
                "reg_write_hklm",
                "HKLM\\SOFTWARE\\mcp-writ-pr30-probe",
                &format!("err:{rc}"),
                &format!("RegCreateKeyExW -> {rc}"),
            ));
        }
        // HKCU write of a test-owned key — allowed even inside AppContainer
        // (package hive); records whether the env keeps a usable HKCU.
        let mut key2: HKEY = std::ptr::null_mut();
        let rc2 = RegCreateKeyExW(
            HKCU,
            sub.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_READ | 0x0002_0006,
            std::ptr::null_mut(),
            &mut key2,
            &mut disp,
        );
        if rc2 == ERROR_SUCCESS {
            RegCloseKey(key2);
            let _ = RegDeleteKeyW(HKCU, sub.as_ptr());
            items.push(attempt(
                "reg_write_hkcu",
                "HKCU\\SOFTWARE\\mcp-writ-pr30-probe",
                "ok",
                "created+deleted",
            ));
        } else {
            items.push(attempt(
                "reg_write_hkcu",
                "HKCU\\SOFTWARE\\mcp-writ-pr30-probe",
                &format!("err:{rc2}"),
                &format!("RegCreateKeyExW -> {rc2}"),
            ));
        }
        // Named object creation — global namespace access check.
        let m = CreateMutexW(
            std::ptr::null_mut(),
            0,
            wide(r"Local\mcp-writ-pr30-mutex").as_ptr(),
        );
        if m.is_null() {
            items.push(attempt(
                "named_mutex",
                r"Local\mcp-writ-pr30-mutex",
                &format!("err:{}", GetLastError()),
                "CreateMutexW failed",
            ));
        } else {
            CloseHandle(m);
            items.push(attempt(
                "named_mutex",
                r"Local\mcp-writ-pr30-mutex",
                "ok",
                "created",
            ));
        }
    }
    // Spawn: a descendant process (grandchild of the runner) — the
    // process-tree leg. `WINISO_SPAWN_GC=1` makes it a long sleeper so the
    // wrapper can prove tree teardown; otherwise a fast sleeper. The
    // image is `WINISO_GC_EXE` when set — under a filesystem sandbox the
    // child's own exe path is typically ungranted, so wrappers place an
    // exe copy inside the RW grant.
    let gc_long = arg("--gc-sleep").is_some() || std::env::var("WINISO_SPAWN_GC").is_ok();
    let gc_ms = arg("--gc-sleep").unwrap_or_else(|| {
        if gc_long {
            "20000".into()
        } else {
            "300".into()
        }
    });
    let gc_label = if gc_long {
        "spawn_grandchild"
    } else {
        "spawn_child"
    };
    let gc_exe = arg("--gc-exe")
        .map(PathBuf::from)
        .or_else(|| std::env::var("WINISO_GC_EXE").ok().map(PathBuf::from))
        .unwrap_or_else(|| std::env::current_exe().unwrap());
    match std::process::Command::new(&gc_exe)
        .args(["sleep", &gc_ms])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => items.push(attempt(
            gc_label,
            &gc_exe.to_string_lossy(),
            "ok",
            &format!("pid={}", child.id()),
        )),
        Err(e) => items.push(attempt(
            gc_label,
            &gc_exe.to_string_lossy(),
            &format!("err:{}", e.raw_os_error().unwrap_or(-1)),
            &e.to_string(),
        )),
    }

    format!(
        "{{\"mode\":\"attempts\",\"context\":{},\"env_seen\":[{}],\"attempts\":[{}]}}",
        token_facts(),
        env_vars.join(","),
        items.join(",")
    )
}

/// Raw Winsock connect with a bounded wait — IPv4 `a.b.c.d:port` only
/// (every probe target is a literal). Returns `("ok", ..)`,
/// `("err:<wsa>", ..)`, or `("timeout", ..)`. WSAStartup failures report
/// their code instead of panicking the way `std::net` would.
fn raw_tcp_connect(addr: &str) -> (String, String) {
    let (ip, port) = match addr.rsplit_once(':') {
        Some((i, p)) => match (parse_ipv4(i), p.parse::<u16>()) {
            (Some(ip), Ok(p)) => (ip, p),
            _ => return ("skipped".into(), "unparseable addr".into()),
        },
        None => return ("skipped".into(), "unparseable addr".into()),
    };
    // sockaddr_in: family(2) + port(be) + addr(be) + 8 zero pad.
    let mut sa = [0u8; 16];
    sa[0] = 2; // AF_INET low byte (little-endian u16)
    sa[2] = (port >> 8) as u8;
    sa[3] = (port & 0xff) as u8;
    sa[4..8].copy_from_slice(&ip);
    unsafe {
        let mut wsa = [0u8; 400];
        let r = WSAStartup(0x0202, wsa.as_mut_ptr());
        if r != 0 {
            return (format!("err:{r}"), format!("WSAStartup -> {r}"));
        }
    }
    // connect() blocks past our patience on filtered egress — run it on
    // a worker; a wedged connect outlives the wait but dies at exit.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || unsafe {
        let s = socket(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
        if s == usize::MAX {
            let e = WSAGetLastError();
            WSACleanup();
            let _ = tx.send(e);
            return;
        }
        let r = connect(s, sa.as_ptr(), sa.len() as i32);
        let e = if r == 0 { 0 } else { WSAGetLastError() };
        closesocket(s);
        WSACleanup();
        let _ = tx.send(e);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok(0) => ("ok".into(), "connected".into()),
        Ok(e) => (format!("err:{e}"), format!("WSA error {e}")),
        Err(_) => ("timeout".into(), "connect did not return in 3s".into()),
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut i = 0;
    for part in s.split('.') {
        if i >= 4 {
            return None;
        }
        out[i] = part.parse::<u8>().ok()?;
        i += 1;
    }
    if i == 4 {
        Some(out)
    } else {
        None
    }
}
