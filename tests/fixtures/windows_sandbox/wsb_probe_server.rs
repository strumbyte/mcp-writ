//! Std-only MCP probe server for the Windows Sandbox validation
//! (`tests/windows_sandbox_vm_e2e.rs`, `docs/validation/windows-sandbox.md`,
//! PR-23).
//!
//! Fork of `tests/fixtures/hyperv/hyperv_probe_server.rs`: compiled by
//! the test via plain `rustc` (no cargo, no crates), staged onto the
//! guest's own NTFS by the relay agent, and spawned as the workload
//! `mcp-secure-runner` wraps. Every tool performs a real guest-side
//! operation so the run produces evidence about the guest's control
//! state, not just relayed strings:
//!
//!   read_file    {path}          open read; content head
//!   create_file  {path,content?} create_new write (DACL grant evidence)
//!   vm_identity  {}              guest OS build (a separate kernel assembled
//!                                from host OS files; build numbers may match),
//!                                memory snapshot, and identity evidence:
//!                                WDAGUtilityAccount user + generated
//!                                hostname, plus this process's
//!                                AppContainer token state and job
//!                                membership — never trusted without
//!                                host-side unit evidence)
//!   net_probe    {addr?}         outbound TCP connect — the policy grants
//!                                no network capability, so a denial shows
//!                                the AppContainer capability check
//!   spawn_child  {}              child-process creation attempt under the
//!                                warden's launch conditions (descendant
//!                                restriction evidence)
//!   env_probe    {}              environment surface (restricted env
//!                                evidence: stripped MCP_* / sentinel vars)
//!
//! A known tool returns `isError=false` even when the operation fails —
//! failure details ride in the result text. Unknown tools get
//! `isError=true`; unknown methods get -32601.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};

// ─── minimal JSON parser (same contract as kata_probe_server.rs) ──────

#[derive(Clone)]
enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    // Parsed for completeness; request fields used here are never arrays.
    #[allow(dead_code)]
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        if let J::Obj(m) = self {
            m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }

    fn as_str(&self) -> Option<&str> {
        if let J::Str(s) = self { Some(s) } else { None }
    }

    fn raw(&self) -> String {
        match self {
            J::Num(n) => n.clone(),
            J::Str(s) => format!("\"{}\"", json_escape(s)),
            J::Bool(b) => b.to_string(),
            _ => "null".to_string(),
        }
    }
}

struct Jp<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Jp<'a> {
    fn new(text: &'a str) -> Self {
        Jp {
            s: text.as_bytes(),
            i: 0,
        }
    }
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Option<J> {
        self.ws();
        match *self.s.get(self.i)? {
            b'{' => self.obj(),
            b'[' => self.arr(),
            b'"' => self.string().map(J::Str),
            b't' => self.lit("true").map(|_| J::Bool(true)),
            b'f' => self.lit("false").map(|_| J::Bool(false)),
            b'n' => self.lit("null").map(|_| J::Null),
            _ => self.num(),
        }
    }
    fn lit(&mut self, w: &str) -> Option<()> {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Some(())
        } else {
            None
        }
    }
    fn num(&mut self) -> Option<J> {
        self.ws();
        let start = self.i;
        while matches!(
            self.s.get(self.i),
            Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        ) {
            self.i += 1;
        }
        (self.i > start).then(|| J::Num(self.s[start..self.i].iter().map(|b| *b as char).collect()))
    }
    fn hex4(&mut self) -> Option<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            v = v * 16 + d as u32;
        }
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        (*self.s.get(self.i)? == b'"').then(|| self.i += 1);
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i) == Some(&b'\\')
                                    && self.s.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return None;
                                    }
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(char::from_u32(cp)?);
                                } else {
                                    return None;
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return None;
                            } else {
                                out.push(char::from_u32(hi)?);
                            }
                        }
                        _ => return None,
                    }
                }
                _ => {
                    // Multi-byte UTF-8 passthrough (same contract as
                    // open_path_server.rs): `c` is the first byte of a
                    // sequence already consumed; re-emit the full sequence.
                    let len = if c < 0x80 {
                        1
                    } else if c < 0xE0 {
                        2
                    } else if c < 0xF0 {
                        3
                    } else {
                        4
                    };
                    let start = self.i - 1;
                    let end = start + len;
                    let chunk = std::str::from_utf8(self.s.get(start..end)?).ok()?;
                    out.push_str(chunk);
                    self.i = end;
                }
            }
        }
    }
    fn obj(&mut self) -> Option<J> {
        (*self.s.get(self.i)? == b'{').then(|| self.i += 1);
        let mut m = Vec::new();
        loop {
            self.ws();
            match self.s.get(self.i)? {
                b'}' => {
                    self.i += 1;
                    return Some(J::Obj(m));
                }
                b',' => self.i += 1,
                _ => {
                    let k = self.string()?;
                    self.ws();
                    (*self.s.get(self.i)? == b':').then(|| self.i += 1);
                    let v = self.value()?;
                    m.push((k, v));
                }
            }
        }
    }
    fn arr(&mut self) -> Option<J> {
        (*self.s.get(self.i)? == b'[').then(|| self.i += 1);
        let mut a = Vec::new();
        loop {
            self.ws();
            match self.s.get(self.i)? {
                b']' => {
                    self.i += 1;
                    return Some(J::Arr(a));
                }
                b',' => self.i += 1,
                _ => a.push(self.value()?),
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ─── minimal Win32 FFI (advapi32/kernel32/ntdll) ───────────────────────
//
// Plain `rustc` on the MSVC target resolves these imports against the
// system libraries — no `windows` crate, matching the fixture's
// cargo-free build contract. All declarations are read-only queries;
// the probe never mutates security state.

#[allow(non_camel_case_types, non_snake_case)]
mod ffi {
    pub type HANDLE = isize;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type LPWSTR = *mut u16;
    pub type PSID = *mut core::ffi::c_void;

    /// TOKEN_QUERY — enough to interrogate the calling process token.
    pub const TOKEN_QUERY: DWORD = 0x0008;
    /// TOKEN_INFORMATION_CLASS::TokenIsAppContainer.
    pub const TOKEN_IS_APP_CONTAINER: DWORD = 29;
    /// TOKEN_INFORMATION_CLASS::TokenAppContainerSid.
    pub const TOKEN_APP_CONTAINER_SID: DWORD = 31;
    /// TOKEN_INFORMATION_CLASS::TokenUser.
    pub const TOKEN_USER: DWORD = 1;
    /// TOKEN_INFORMATION_CLASS::TokenGroups.
    pub const TOKEN_GROUPS: DWORD = 2;

    /// RTL_OSVERSIONINFOW (OSVERSIONINFOW without the EX tail).
    #[repr(C)]
    pub struct OSVERSIONINFOW {
        pub dw_os_version_info_size: DWORD,
        pub dw_major_version: DWORD,
        pub dw_minor_version: DWORD,
        pub dw_build_number: DWORD,
        pub dw_platform_id: DWORD,
        pub sz_csd_version: [u16; 128],
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct MEMORYSTATUSEX {
        pub length: DWORD,
        pub load: DWORD,
        pub total_physical: u64,
        pub available_physical: u64,
        pub total_page_file: u64,
        pub available_page_file: u64,
        pub total_virtual: u64,
        pub available_virtual: u64,
        pub available_extended_virtual: u64,
    }

    /// TOKEN_USER { SidAndAttributes{ Sid, Attributes } } — only the SID
    /// pointer is read.
    #[repr(C)]
    pub struct TOKEN_USER_ {
        pub sid: PSID,
        pub attributes: DWORD,
    }

    /// SID_AND_ATTRIBUTES — TokenGroups returns an array of these.
    #[repr(C)]
    pub struct SID_AND_ATTRIBUTES_ {
        pub sid: PSID,
        pub attributes: DWORD,
    }

    /// TOKEN_GROUPS { GroupCount, Groups[ANYSIZE_ARRAY] }.
    #[repr(C)]
    pub struct TOKEN_GROUPS_ {
        pub group_count: DWORD,
        pub groups: [SID_AND_ATTRIBUTES_; 1],
    }

    /// TOKEN_APPCONTAINER_INFORMATION { TokenAppContainer }.
    #[repr(C)]
    pub struct TOKEN_APPCONTAINER_INFORMATION_ {
        pub token_app_container: PSID,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetCurrentProcess() -> HANDLE;
        pub fn CloseHandle(h: HANDLE) -> BOOL;
        pub fn IsProcessInJob(process: HANDLE, job: HANDLE, result: *mut BOOL) -> BOOL;
        pub fn GetComputerNameW(buffer: LPWSTR, size: *mut DWORD) -> BOOL;
        pub fn GetLastError() -> DWORD;
        pub fn GlobalMemoryStatusEx(status: *mut MEMORYSTATUSEX) -> BOOL;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn OpenProcessToken(process: HANDLE, access: DWORD, token: *mut HANDLE) -> BOOL;
        pub fn GetTokenInformation(
            token: HANDLE,
            class: DWORD,
            buf: *mut core::ffi::c_void,
            buf_len: DWORD,
            return_len: *mut DWORD,
        ) -> BOOL;
        pub fn ConvertSidToStringSidW(sid: PSID, string_sid: *mut LPWSTR) -> BOOL;
        pub fn GetUserNameW(buffer: LPWSTR, size: *mut DWORD) -> BOOL;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        pub fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> i32;
    }

    // LocalFree lives in kernel32 on modern Windows; keeping it under
    // kernel32 avoids a sechost dependency.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn LocalFree(mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// `S-1-…` text for a raw SID, or `?` when the conversion fails.
fn sid_string(sid: ffi::PSID) -> String {
    if sid.is_null() {
        return "null".into();
    }
    unsafe {
        let mut out: ffi::LPWSTR = std::ptr::null_mut();
        if ffi::ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
            return "?".into();
        }
        let mut len = 0usize;
        while *out.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
        ffi::LocalFree(out.cast());
        s
    }
}

/// Guest kernel version. Windows Sandbox boots a scratch image assembled
/// from the host's own files, so the guest reports the *same* build as
/// the host — unlike the Hyper-V unit's image-kernel split, the build
/// number cannot discriminate substrate here. Combine guest identity with
/// the owned management ID and authenticated relay, not a global vmwp count.
fn os_version() -> String {
    let mut v = ffi::OSVERSIONINFOW {
        dw_os_version_info_size: std::mem::size_of::<ffi::OSVERSIONINFOW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };
    unsafe {
        if ffi::RtlGetVersion(&mut v) != 0 {
            return "?".into();
        }
    }
    format!(
        "{}.{}.{}",
        v.dw_major_version, v.dw_minor_version, v.dw_build_number
    )
}

/// Token facts this process carries: whether it is an AppContainer
/// token, its AppContainer package SID, its user SID, and the number of
/// capability/group SIDs attached.
fn token_facts() -> String {
    unsafe {
        let mut token: ffi::HANDLE = 0;
        if ffi::OpenProcessToken(ffi::GetCurrentProcess(), ffi::TOKEN_QUERY, &mut token) == 0 {
            return format!("OpenProcessToken failed: gle={}", ffi::GetLastError());
        }
        let mut out = String::new();

        // TokenIsAppContainer → DWORD.
        let mut is_ac: ffi::DWORD = 0;
        let mut retlen: ffi::DWORD = 0;
        if ffi::GetTokenInformation(
            token,
            ffi::TOKEN_IS_APP_CONTAINER,
            (&mut is_ac as *mut ffi::DWORD).cast(),
            std::mem::size_of::<ffi::DWORD>() as u32,
            &mut retlen,
        ) != 0
        {
            out.push_str(&format!("appcontainer={}", is_ac != 0));
        } else {
            out.push_str(&format!("appcontainer=gle{}", ffi::GetLastError()));
        }

        // TokenAppContainerSid → TOKEN_APPCONTAINER_INFORMATION { PSID } —
        // the SID bytes land inside the same buffer, so size it first.
        let mut need: ffi::DWORD = 0;
        let _ = ffi::GetTokenInformation(
            token,
            ffi::TOKEN_APP_CONTAINER_SID,
            std::ptr::null_mut(),
            0,
            &mut need,
        );
        if need > 0 {
            let mut buf = vec![0u64; (need as usize).div_ceil(8)];
            if ffi::GetTokenInformation(
                token,
                ffi::TOKEN_APP_CONTAINER_SID,
                buf.as_mut_ptr().cast(),
                need,
                &mut retlen,
            ) != 0
            {
                let info = &*(buf.as_ptr() as *const ffi::TOKEN_APPCONTAINER_INFORMATION_);
                out.push_str(&format!(
                    " appcontainer_sid={}",
                    sid_string(info.token_app_container)
                ));
            }
        }

        // TokenUser → TOKEN_USER { SID_AND_ATTRIBUTES } — same two-call
        // shape: the user SID follows the struct inside the buffer.
        let mut need: ffi::DWORD = 0;
        let _ =
            ffi::GetTokenInformation(token, ffi::TOKEN_USER, std::ptr::null_mut(), 0, &mut need);
        if need > 0 {
            let mut buf = vec![0u64; (need as usize).div_ceil(8)];
            if ffi::GetTokenInformation(
                token,
                ffi::TOKEN_USER,
                buf.as_mut_ptr().cast(),
                need,
                &mut retlen,
            ) != 0
            {
                let user = &*(buf.as_ptr() as *const ffi::TOKEN_USER_);
                out.push_str(&format!(" user_sid={}", sid_string(user.sid)));
            }
        }

        // TokenGroups → count + ALL APPLICATION PACKAGES presence.
        let mut need: ffi::DWORD = 0;
        let _ =
            ffi::GetTokenInformation(token, ffi::TOKEN_GROUPS, std::ptr::null_mut(), 0, &mut need);
        if need > 0 {
            // `Vec<u64>` so the buffer's alignment satisfies the PSID
            // pointers inside TOKEN_GROUPS — `Vec<u8>` is only align-1.
            let mut buf = vec![0u64; (need as usize).div_ceil(8)];
            if ffi::GetTokenInformation(
                token,
                ffi::TOKEN_GROUPS,
                buf.as_mut_ptr().cast(),
                need,
                &mut retlen,
            ) != 0
            {
                let groups = &*(buf.as_ptr() as *const ffi::TOKEN_GROUPS_);
                let count = groups.group_count as usize;
                let first = groups.groups.as_ptr();
                let mut aap = false;
                let mut names = String::new();
                for i in 0..count {
                    let sid = sid_string((*first.add(i)).sid);
                    if sid == "S-1-15-2-1" {
                        aap = true;
                    }
                    names.push_str(&sid);
                    names.push(',');
                }
                let _ = names.pop();
                out.push_str(&format!(
                    " groups={count} all_app_packages={aap} group_sids=[{names}]"
                ));
            }
        }

        let mut in_job: ffi::BOOL = 0;
        if ffi::IsProcessInJob(ffi::GetCurrentProcess(), 0, &mut in_job) != 0 {
            out.push_str(&format!(" in_job={}", in_job != 0));
        }

        ffi::CloseHandle(token);
        out
    }
}

// ─── tools ───────────────────────────────────────────────────────────

fn text_result(id_raw: String, text: String, is_error: bool) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{t}\"}}],\"isError\":{e}}}}}",
        id = id_raw,
        t = json_escape(&text),
        e = is_error
    )
}

fn rpc_error(id_raw: String, code: i64, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":\"{m}\"}}}}",
        id = id_raw,
        code = code,
        m = json_escape(message)
    )
}

fn tool_read_file(args: &J) -> String {
    let Some(path) = args.get("path").and_then(J::as_str) else {
        return "missing arguments.path".to_string();
    };
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = vec![0u8; 256];
            let n = io::Read::read(&mut f, &mut buf).unwrap_or(0);
            format!(
                "opened {path}: head=\"{}\"",
                json_escape(&String::from_utf8_lossy(&buf[..n]))
            )
        }
        Err(e) => format!("open {path} failed: {e}"),
    }
}

fn tool_create_file(args: &J) -> String {
    let Some(path) = args.get("path").and_then(J::as_str) else {
        return "missing arguments.path".to_string();
    };
    let content = args.get("content").and_then(J::as_str).unwrap_or("");
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => match f.write_all(content.as_bytes()) {
            Ok(()) => format!("created {path} ({} bytes)", content.len()),
            Err(e) => format!("write {path} failed: {e}"),
        },
        Err(e) => format!("create {path} failed: {e}"),
    }
}

/// Guest-side identity reported by the trusted fixture: the sandbox's generated
/// hostname and `WDAGUtilityAccount` user, the AppContainer token state
/// the warden produced, job membership, and the guest build (which
/// matches the host's — Windows Sandbox runs host binaries).
fn tool_vm_identity() -> String {
    let mut computer = [0u16; 256];
    let mut cn_len = computer.len() as u32;
    let computer_name = unsafe {
        if ffi::GetComputerNameW(computer.as_mut_ptr(), &mut cn_len) != 0 {
            wide_to_string(&computer)
        } else {
            "?".into()
        }
    };
    let mut user = [0u16; 256];
    let mut un_len = user.len() as u32;
    let user_name = unsafe {
        if ffi::GetUserNameW(user.as_mut_ptr(), &mut un_len) != 0 {
            wide_to_string(&user)
        } else {
            "?".into()
        }
    };
    let mut memory = ffi::MEMORYSTATUSEX {
        length: std::mem::size_of::<ffi::MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let memory_facts = unsafe {
        if ffi::GlobalMemoryStatusEx(&mut memory) != 0 {
            format!(
                "guest_total_physical_bytes={} guest_available_physical_bytes={}",
                memory.total_physical, memory.available_physical
            )
        } else {
            format!("GlobalMemoryStatusEx failed: gle={}", ffi::GetLastError())
        }
    };
    format!(
        "os.version={} computer={computer_name} user={user_name} | {memory_facts} | {}",
        os_version(),
        token_facts()
    )
}

/// The fixture policy grants no network capability at all — an outbound
/// TCP connect must surface the AppContainer capability denial
/// (WSAEACCES/10013) rather than reach a SYN.
fn tool_net_probe(args: &J) -> String {
    let addr = args
        .get("addr")
        .and_then(J::as_str)
        .unwrap_or("192.0.2.1:80");
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => {
            match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2)) {
                Ok(_) => format!("connect {addr} succeeded (unexpected)"),
                Err(e) => format!("connect {addr} failed: {e}"),
            }
        }
        Err(e) => format!("connect {addr} failed: invalid address: {e}"),
    }
}

/// Descendant creation under the launch conditions the warden sets.
/// Mirrors `windows_sandbox`'s `sandboxed_workload_cannot_spawn_children`
/// observation: an AppContainer child launched through this pipeline
/// inherits a working directory outside its grants, has no console, and
/// receives only the stdio pipe handles — the inner `cmd` launch is
/// denied. The leg records whichever way the guest actually behaves.
fn tool_spawn_child() -> String {
    match std::process::Command::new("cmd.exe")
        .args(["/c", "echo CHILD_OK"])
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!(
                "spawn ok: status={} stdout={:?} stderr={:?}",
                out.status.code().map_or("?".into(), |c| c.to_string()),
                stdout.trim(),
                stderr.trim()
            )
        }
        Err(e) => format!("spawn failed: {e}"),
    }
}

/// The environment the child actually received — `restrict_environment`
/// evidence. MCP_* control variables must never reach the workload, and
/// the restricted block keeps only the policy-allowed names plus the
/// runner's minimal PATH/TMP plumbing.
fn tool_env_probe() -> String {
    let pick = |name: &str| match std::env::var(name) {
        Ok(v) => v,
        Err(_) => "<absent>".to_string(),
    };
    let mcp_vars: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("MCP_"))
        .collect();
    format!(
        "USERNAME={} PATH={} TEMP={} TMP={} mcp_vars_present={:?}",
        pick("USERNAME"),
        pick("PATH"),
        pick("TEMP"),
        pick("TMP"),
        mcp_vars
    )
}

/// Abnormal-termination leg: the workload exits with a chosen nonzero
/// code — the runner must propagate it, write the launch report, and let
/// the utility VM unwind. `exit` rather than an access-violation crash so
/// the expected exit code is deterministic.
fn tool_exit_child(args: &J) -> String {
    let code = args
        .get("code")
        .and_then(|j| match j {
            J::Num(n) => n.parse::<i32>().ok(),
            _ => None,
        })
        .unwrap_or(3);
    std::process::exit(code);
}

fn tool_echo(args: &J) -> String {
    args.get("text")
        .and_then(J::as_str)
        .unwrap_or("")
        .to_string()
}

fn tools_list() -> &'static str {
    "{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"create_file\"},{\"name\":\"vm_identity\"},{\"name\":\"net_probe\"},{\"name\":\"spawn_child\"},{\"name\":\"env_probe\"},{\"name\":\"exit_child\"},{\"name\":\"echo\"}]}"
}

// ─── main loop ───────────────────────────────────────────────────────

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let mut p = Jp::new(&line);
        let Some(req) = p.value() else {
            continue;
        };
        let method = req
            .get("method")
            .and_then(J::as_str)
            .unwrap_or("")
            .to_string();
        let id_raw = req
            .get("id")
            .map(|j| j.raw())
            .unwrap_or_else(|| "null".into());
        let is_request = req.get("id").is_some();
        match method.as_str() {
            "initialize" => {
                writeln!(
                    stdout.lock(),
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"wsb-probe\",\"version\":\"0\"}}}}}}",
                    id = id_raw
                )
                .ok();
            }
            "tools/list" => {
                writeln!(
                    stdout.lock(),
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{list}}}",
                    id = id_raw,
                    list = tools_list()
                )
                .ok();
            }
            "tools/call" => {
                let params = req.get("params");
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(J::as_str)
                    .unwrap_or("")
                    .to_string();
                let args = params
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(J::Obj(vec![]));
                let out = match name.as_str() {
                    "read_file" => (tool_read_file(&args), false),
                    "create_file" => (tool_create_file(&args), false),
                    "vm_identity" => (tool_vm_identity(), false),
                    "net_probe" => (tool_net_probe(&args), false),
                    "spawn_child" => (tool_spawn_child(), false),
                    "env_probe" => (tool_env_probe(), false),
                    "exit_child" => (tool_exit_child(&args), false),
                    "echo" => (tool_echo(&args), false),
                    _ => (format!("unknown tool '{name}'"), true),
                };
                writeln!(stdout.lock(), "{}", text_result(id_raw, out.0, out.1)).ok();
            }
            m if m.starts_with("notifications/") => {}
            _ if is_request => {
                writeln!(
                    stdout.lock(),
                    "{}",
                    rpc_error(id_raw, -32601, &format!("method not found: {method}"))
                )
                .ok();
            }
            _ => {}
        }
        stdout.lock().flush().ok();
    }
}
