//! Shared spawn plumbing (ac-run / psec-run): proc-thread attribute
//! lists, stdio pipes, Job kill-on-close teardown, child JSON capture.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use crate::ffi::*;
use crate::helpers::{js, wide};

pub(crate) struct SpawnOut {
    pub(crate) ok: bool,
    pub(crate) detail: String,
    pub(crate) child_json: String,
    pub(crate) child_pid: u32,
    pub(crate) gc_pid: Option<u32>,
    /// `Some(true)` when a spawned grandchild was dead once the job
    /// handle closed — the descendant-teardown evidence.
    pub(crate) gc_killed: Option<bool>,
    #[allow(dead_code)]
    pub(crate) create_err: u32,
}

/// Spawn `self attempts` with caller-provided proc-thread attributes
/// (each `(attr_id, value_ptr, value_size)`), capture the child's JSON
/// line, wait with a deadline. The attribute list always adds
/// PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming the child's stdin/stdout
/// pipes — mirroring the product path, and required because a
/// reserved-but-unpopulated attribute slot is rejected by
/// `CreateProcessW` (ERROR_INVALID_PARAMETER). Child stdin sees EOF;
/// stdout drains on a helper thread so a large write cannot deadlock
/// the wait. A Job object (kill-on-close) owns the child so descendants
/// are reaped when the handle closes — the same teardown shape the
/// product uses.
/// Quote one argument the way `CommandLineToArgvW` (and the CRT argv
/// parser built on it) reads it back: bare when the arg has no spaces,
/// tabs, or quotes; otherwise wrap in quotes with backslashes doubled
/// before a quote and at the end of the arg. Empty args always quote.
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '"')
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // 2n+1 backslashes so the quote survives as a literal.
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                backslashes = 0;
                out.push('"');
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2)); // trailing run doubles
    out.push('"');
    out
}

fn join_argv(args: &[String]) -> String {
    args.iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `image` is the spawned executable (`lpApplicationName`); `args` is the
/// verbatim command tail. For the `attempts` battery callers pass the
/// probe's own exe; `--image` legs pass an external binary (e.g. node.exe)
/// to measure whether real-world launch conditions hold under the token.
pub(crate) unsafe fn spawn_wrapped(
    image: &Path,
    args: &[String],
    attrs: &[(usize, *const c_void, usize)],
) -> SpawnOut {
    let mut out = SpawnOut {
        ok: false,
        detail: String::new(),
        child_json: String::new(),
        child_pid: 0,
        gc_pid: None,
        gc_killed: None,
        create_err: 0,
    };
    let mut r_out: HANDLE = std::ptr::null_mut();
    let mut w_out: HANDLE = std::ptr::null_mut();
    let mut r_in: HANDLE = std::ptr::null_mut();
    let mut w_in: HANDLE = std::ptr::null_mut();
    if CreatePipe(&mut r_out, &mut w_out, std::ptr::null_mut(), 0) == 0
        || CreatePipe(&mut r_in, &mut w_in, std::ptr::null_mut(), 0) == 0
    {
        out.detail = format!("CreatePipe failed: {}", GetLastError());
        return out;
    }
    // Only the child-facing ends are inheritable, and the handle-list
    // attribute names exactly those two.
    SetHandleInformation(r_in, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(w_out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    // Attribute list: caller attrs + handle list. `attr_count` must equal
    // the number of UpdateProcThreadAttribute calls — a counted but
    // unset slot is an invalid attribute.
    let attr_count = attrs.len() as u32 + 1;
    let mut size = 0usize;
    InitializeProcThreadAttributeList(std::ptr::null_mut(), attr_count, 0, &mut size);
    let mut attr_buf = vec![0u8; size + 64];
    let attr_list = attr_buf.as_mut_ptr() as *mut c_void;
    if InitializeProcThreadAttributeList(attr_list, attr_count, 0, &mut size) == 0 {
        for h in [r_out, w_out, r_in, w_in] {
            CloseHandle(h);
        }
        out.detail = format!(
            "InitializeProcThreadAttributeList failed: {}",
            GetLastError()
        );
        return out;
    }
    let mut ok_attr = true;
    for &(attr, val, vsize) in attrs {
        if UpdateProcThreadAttribute(
            attr_list,
            0,
            attr,
            val,
            vsize,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            out.detail = format!(
                "UpdateProcThreadAttribute(0x{attr:x}) failed: {}",
                GetLastError()
            );
            ok_attr = false;
        }
    }
    let handles = [r_in, w_out];
    if UpdateProcThreadAttribute(
        attr_list,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles.as_ptr() as *const c_void,
        std::mem::size_of::<HANDLE>() * 2,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) == 0
    {
        out.detail
            .push_str(&format!("; handle-list attr failed: {}", GetLastError()));
        ok_attr = false;
    }
    if !ok_attr {
        DeleteProcThreadAttributeList(attr_list);
        for h in [r_out, w_out, r_in, w_in] {
            CloseHandle(h);
        }
        return out;
    }

    let cmdline = format!("\"{}\" {}", image.to_string_lossy(), join_argv(args));
    let mut cmd: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let si = StartupInfoExW {
        cb: std::mem::size_of::<StartupInfoExW>() as u32,
        flags: STARTF_USESTDHANDLES,
        std_input: r_in,
        std_output: w_out,
        std_error: w_out,
        attr_list,
        ..std::mem::zeroed()
    };
    let mut pi = ProcessInformation {
        process: std::ptr::null_mut(),
        thread: std::ptr::null_mut(),
        process_id: 0,
        thread_id: 0,
    };
    let flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    let okc = CreateProcessW(
        wide(&image.to_string_lossy()).as_ptr(),
        cmd.as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        1,
        flags,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &si,
        &mut pi,
    );
    DeleteProcThreadAttributeList(attr_list);
    if okc == 0 {
        out.create_err = GetLastError();
        out.detail = format!("CreateProcessW failed: {}", out.create_err);
        for h in [r_out, w_out, r_in, w_in] {
            CloseHandle(h);
        }
        return out;
    }
    out.child_pid = pi.process_id;
    // Parent keeps only the ends it uses.
    CloseHandle(w_out);
    CloseHandle(r_in);
    CloseHandle(w_in);

    // Job: the tree dies with the runner.
    let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null_mut());
    if !job.is_null() {
        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION: LimitFlags at offset 16.
        let mut buf = [0u8; 256];
        let flags_ptr = buf.as_mut_ptr().add(16) as *mut u32;
        *flags_ptr = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let _ = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            buf.as_ptr() as *const c_void,
            buf.len() as u32,
        );
        let _ = AssignProcessToJobObject(job, pi.process);
    }

    ResumeThread(pi.thread);
    CloseHandle(pi.thread);

    // Drain stdout on a helper thread, then bound-wait on the process.
    let r_out_usize = r_out as usize;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut got = 0u32;
            let okr = ReadFile(
                r_out_usize as HANDLE,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            );
            if okr == 0 || got == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..got as usize]);
        }
        buf
    });
    let wait = WaitForSingleObject(pi.process, 30_000);
    if wait == WAIT_TIMEOUT && !job.is_null() {
        TerminateJobObject(job, 1);
    }
    let _ = WaitForSingleObject(pi.process, 5_000);
    let stdout = reader.join().unwrap_or_default();
    out.child_json = String::from_utf8_lossy(&stdout).trim().to_string();
    out.ok = wait == WAIT_OBJECT_0;
    if wait == WAIT_TIMEOUT {
        out.detail = "child deadline elapsed — terminated via job".into();
    }
    if job.is_null() {
        out.detail.push_str("; job object create failed");
    }

    // Descendant check: the child's attempts JSON reports its spawned
    // grandchild pid; closing the job handle must reap it.
    if let Some(pid) = extract_pid(&out.child_json) {
        let gc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid);
        if !gc.is_null() {
            out.gc_pid = Some(pid);
            if WaitForSingleObject(gc, 0) == WAIT_TIMEOUT && !job.is_null() {
                CloseHandle(job);
                let dead = WaitForSingleObject(gc, 5_000) == WAIT_OBJECT_0;
                out.gc_killed = Some(dead);
                out.detail
                    .push_str(&format!("; gc pid={pid} kill-on-close dead={dead}"));
                CloseHandle(gc);
                CloseHandle(pi.process);
                CloseHandle(r_out);
                return out;
            }
            CloseHandle(gc);
        }
    }
    if !job.is_null() {
        CloseHandle(job);
    }
    CloseHandle(pi.process);
    CloseHandle(r_out);
    out
}

/// argv for an `attempts` child carrying the WINISO_* context — used by
/// wrappers so the battery works even where the env block is not
/// inherited into the sandboxed process.
pub(crate) fn attempts_args(gc_exe: Option<&PathBuf>, net_allow: Option<String>) -> Vec<String> {
    let mut args = vec!["attempts".to_string()];
    for (env_var, flag) in [
        ("WINISO_RO_DIR", "--ro"),
        ("WINISO_RW_DIR", "--rw"),
        ("WINISO_DENY_DIR", "--deny"),
        ("WINISO_UNGRANTED_DIR", "--ungranted"),
        ("WINISO_NET_ADDR", "--net-deny"),
    ] {
        if let Ok(v) = std::env::var(env_var) {
            args.push(flag.into());
            args.push(v);
        }
    }
    if let Some(a) = net_allow {
        args.push("--net-allow".into());
        args.push(a);
    }
    args.push("--gc-sleep".into());
    args.push("20000".into());
    if let Some(gc) = gc_exe {
        args.push("--gc-exe".into());
        args.push(gc.to_string_lossy().into_owned());
    }
    args
}

/// `--image <exe> <argv...>` splits a run-mode argv into an external
/// child image plus its verbatim tail. Present ⇒ the wrapper spawns
/// that exe with the tail instead of self + `attempts` args.
pub(crate) fn split_image(args: &[String]) -> (Option<PathBuf>, Vec<String>) {
    match args.iter().position(|a| a == "--image") {
        Some(pos) => (
            args.get(pos + 1).map(PathBuf::from),
            args.get(pos + 2..).unwrap_or(&[]).to_vec(),
        ),
        None => (None, Vec::new()),
    }
}

/// Bind an ephemeral loopback listener for the network `allow` leg —
/// connect(2) completes on the backlog, no accept needed, but the
/// listener must stay alive until the child has run.
pub(crate) fn bind_loopback() -> Option<(std::net::TcpListener, String)> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let addr = l.local_addr().ok()?.to_string();
    Some((l, addr))
}

/// A child's stdout is embedded verbatim only when it is one complete
/// JSON object — a sandboxed child that panics mid-emit (LPAC
/// `WSAStartup`, …) must not corrupt the parent's report. Otherwise the
/// raw text goes to `child_stdout` and `child` stays `null`.
pub(crate) fn child_json_or_null(raw: &str) -> String {
    let t = raw.trim().trim_start_matches('\u{feff}');
    if t.starts_with('{') && t.ends_with('}') {
        t.to_string()
    } else {
        "null".into()
    }
}

/// `,"child_stdout":"..."` for the non-JSON child case — the evidence of
/// *why* the child report failed belongs in the record, not discarded.
pub(crate) fn child_stdout_field(raw: &str) -> String {
    let t = raw.trim().trim_start_matches('\u{feff}');
    if t.is_empty() || (t.starts_with('{') && t.ends_with('}')) {
        String::new()
    } else {
        format!(",\"child_stdout\":{}", js(t))
    }
}

/// Pull the grandchild pid out of the child's attempts JSON.
fn extract_pid(json: &str) -> Option<u32> {
    let idx = json.find("\"pid=")?;
    let rest = &json[idx + 5..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}
