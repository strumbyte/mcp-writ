//! PR-30 Windows isolation candidate probe — one std-only binary that
//! measures the new Windows isolation mechanisms (PSEC / BaseContainer,
//! IsolationSession, Win32 app isolation packaging signals) against the
//! existing AppContainer baseline. Never wired into the product launch
//! path; compiled on demand by `tests/windows_isolation_e2e.rs` and by
//! `scripts/validate-windows-isolation.ps1`.
//!
//! Evidence-tier discipline (same contract as `src/container/windows_probe.rs`):
//!
//! - **presence** — file/service/registry artifacts exist (`facts`)
//! - **contract answers** — API-set implementation, export resolution,
//!   version/support queries, WinRT activation (`contracts`). An answer
//!   is never promoted to "the runtime contract works".
//! - **runtime** — real environment creation + a spawned child running
//!   the `attempts` battery (`ac-run`, `psec-run`). Denials are the
//!   data: each attempt records what the OS actually did.
//!
//! Bounded and owned: no elevation, no service control, no Windows
//! feature changes, no store/package installs, no registry writes
//! outside a test-owned HKCU key (attempt leg), no ACL changes outside
//! paths the caller created and restores (`ac-run`). `psec-run` creates
//! a server-side security environment for a single child and closes it;
//! IsolationSession's session/user mutating legs are NOT here — they
//! belong to the dedicated Insider lab (`-Lab` script legs) since they
//! create local users and sessions.
//!
//! Modes: `facts` | `contracts` | `attempts` | `ac-run` | `psec-run` |
//! `sleep <ms>` | `spec-file <out>` (write the PSEC spec bytes for
//! offline inspection). All machine output is one JSON object on
//! stdout; diagnostics go to stderr.

#![cfg(windows)]

use std::ffi::c_void;
use std::io::Write;
use std::path::{Path, PathBuf};

// ─── FFI ────────────────────────────────────────────────────────────────────

type HANDLE = *mut c_void;
type HRESULT = i32;
type BOOL = i32;
type PSID = *mut c_void;
type HKEY = *mut c_void;

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
const WAIT_TIMEOUT: u32 = 0x102;
const WAIT_OBJECT_0: u32 = 0;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const TOKEN_QUERY: u32 = 0x0008;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

// Proc-thread attribute ids (ProcThreadAttributeValue | PROC_THREAD_ATTRIBUTE_INPUT).
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 0x0002_0023;

const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SET_ACCESS: u32 = 2;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;
const TRUSTEE_IS_SID: u32 = 0;
const TRUSTEE_IS_UNKNOWN: u32 = 0;
const GENERIC_ALL: u32 = 0x1000_0000;
/// GENERIC_READ (0x8000_0000) | GENERIC_EXECUTE (0x2000_0000).
const GENERIC_READ_EXECUTE: u32 = 0xA000_0000;

const KEY_READ: u32 = 0x0002_0019; // KEY_QUERY_VALUE|ENUMERATE|NOTIFY|READ_CONTROL-ish (STANDARD_RIGHTS_READ composite)
const HKLM: HKEY = 0x8000_0002usize as HKEY;
const HKCU: HKEY = 0x8000_0001usize as HKEY;
const ERROR_SUCCESS: u32 = 0;

#[repr(C)]
struct ProcessInformation {
    process: HANDLE,
    thread: HANDLE,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
struct SecurityCapabilities {
    appcontainer_sid: PSID,
    capabilities: *mut c_void,
    capability_count: u32,
    reserved: u32,
}

#[repr(C)]
struct StartupInfoExW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count: u32,
    y_count: u32,
    fill: u32,
    flags: u32,
    show_window: u16,
    reserved2: u16,
    reserved2_ptr: *mut u8,
    std_input: HANDLE,
    std_output: HANDLE,
    std_error: HANDLE,
    attr_list: *mut c_void,
}

#[repr(C)]
struct OsVersionInfoW {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
}

#[repr(C)]
struct ExplicitAccessW {
    access_permissions: u32,
    access_mode: u32,
    inheritance: u32,
    trustee_multiple: *mut c_void,
    trustee_op: u32,
    trustee_form: u32,
    trustee_type: u32,
    trustee_name: *mut c_void, // PSID when TRUSTEE_IS_SID
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: HANDLE, flags: u32) -> HANDLE;
    fn GetProcAddress(module: HANDLE, name: *const u8) -> *mut c_void;
    fn FreeLibrary(m: HANDLE) -> BOOL;
    fn GetLastError() -> u32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetCurrentProcessId() -> u32;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn ReadFile(h: HANDLE, buf: *mut u8, len: u32, read: *mut u32, ov: *mut c_void) -> BOOL;
    fn CreatePipe(read: *mut HANDLE, write: *mut HANDLE, sa: *const c_void, size: u32) -> BOOL;
    fn SetHandleInformation(h: HANDLE, mask: u32, flags: u32) -> BOOL;
    fn CreateProcessW(
        app: *const u16,
        cmd: *mut u16,
        pattr: *const c_void,
        tattr: *const c_void,
        inherit: BOOL,
        flags: u32,
        env: *const c_void,
        cwd: *const u16,
        si: *const StartupInfoExW,
        pi: *mut ProcessInformation,
    ) -> BOOL;
    fn CreateJobObjectW(sa: *const c_void, name: *const u16) -> HANDLE;
    fn SetInformationJobObject(job: HANDLE, class: u32, info: *const c_void, len: u32) -> BOOL;
    fn AssignProcessToJobObject(job: HANDLE, proc: HANDLE) -> BOOL;
    fn ResumeThread(thread: HANDLE) -> u32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn TerminateJobObject(job: HANDLE, code: u32) -> BOOL;
    fn OpenProcess(access: u32, inherit: BOOL, pid: u32) -> HANDLE;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> BOOL;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attr: usize,
        value: *const c_void,
        size: usize,
        prev: *mut c_void,
        ret: *mut usize,
    ) -> BOOL;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateMutexW(sa: *const c_void, owner: BOOL, name: *const u16) -> HANDLE;
    fn Sleep(ms: u32);
    fn LocalFree(p: *mut c_void) -> *mut c_void;
}

#[link(name = "kernelbase", kind = "raw-dylib")]
unsafe extern "system" {
    fn IsApiSetImplemented(contract: *const u8) -> BOOL;
    fn CreateAppContainerProfile(
        name: *const u16,
        display: *const u16,
        desc: *const u16,
        caps: *const c_void,
        cap_count: u32,
        sid: *mut PSID,
    ) -> HRESULT;
    fn DeleteAppContainerProfile(name: *const u16) -> HRESULT;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: HKEY, sub: *const u16, opts: u32, access: u32, out: *mut HKEY) -> u32;
    fn RegQueryValueExW(
        key: HKEY,
        name: *const u16,
        res: *mut u32,
        ty: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> u32;
    fn RegCloseKey(key: HKEY) -> u32;
    fn RegCreateKeyExW(
        key: HKEY,
        sub: *const u16,
        res: u32,
        class: *mut u16,
        opts: u32,
        access: u32,
        sa: *const c_void,
        out: *mut HKEY,
        disp: *mut u32,
    ) -> u32;
    fn RegDeleteKeyW(key: HKEY, sub: *const u16) -> u32;
    fn OpenProcessToken(proc: HANDLE, access: u32, out: *mut HANDLE) -> BOOL;
    fn GetTokenInformation(
        token: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> BOOL;
    fn ConvertSidToStringSidW(sid: PSID, out: *mut *mut u16) -> BOOL;
    fn ConvertStringSidToSidW(s: *const u16, sid: *mut PSID) -> BOOL;
    fn GetNamedSecurityInfoW(
        name: *const u16,
        obj_type: u32,
        info: u32,
        owner: *mut PSID,
        group: *mut PSID,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        sd: *mut *mut c_void,
    ) -> u32;
    fn SetNamedSecurityInfoW(
        name: *mut u16,
        obj_type: u32,
        info: u32,
        owner: PSID,
        group: PSID,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;
    fn SetEntriesInAclW(
        count: u32,
        ea: *const ExplicitAccessW,
        old: *const c_void,
        new_acl: *mut *mut c_void,
    ) -> u32;
    fn FreeSid(sid: PSID) -> PSID;
}

#[link(name = "version", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetFileVersionInfoSizeExW(flags: u32, name: *const u16, handle: *mut u32) -> u32;
    fn GetFileVersionInfoExW(
        flags: u32,
        name: *const u16,
        handle: u32,
        len: u32,
        data: *mut c_void,
    ) -> BOOL;
    fn VerQueryValueW(
        data: *const c_void,
        sub: *const u16,
        buf: *mut *mut c_void,
        len: *mut u32,
    ) -> BOOL;
}

#[link(name = "combase", kind = "raw-dylib")]
unsafe extern "system" {
    fn RoInitialize(kind: u32) -> HRESULT;
    fn RoGetActivationFactory(
        name: *const c_void,
        iid: *const c_void,
        out: *mut *mut c_void,
    ) -> HRESULT;
    fn WindowsCreateString(src: *const u16, len: u32, out: *mut *mut c_void) -> HRESULT;
    fn WindowsDeleteString(s: *mut c_void) -> HRESULT;
    fn WindowsGetStringRawBuffer(s: *const c_void, len: *mut u32) -> *const u16;
}

#[link(name = "ole32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CoUninitialize();
    fn CoTaskMemFree(p: *mut c_void);
}

// Raw Winsock2 — `std::net::TcpStream` *panics* when WSAStartup fails
// (LPAC denies the provider init), so the probe drives ws2_32 directly
// and records the real WSA codes instead of dying mid-JSON.
#[link(name = "ws2_32", kind = "raw-dylib")]
unsafe extern "system" {
    fn WSAStartup(req: u16, data: *mut u8) -> i32;
    fn WSACleanup() -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> usize;
    fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn WSAGetLastError() -> i32;
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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

fn js(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

fn jopt(s: Option<String>) -> String {
    s.map(|v| js(&v)).unwrap_or_else(|| "null".into())
}

fn sys32_path(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(name)
}

fn hr_str(hr: i32) -> String {
    format!("0x{hr:08x}")
}

/// One JSON record per file probe: presence + version resource.
fn file_fact(name: &str) -> String {
    let path = sys32_path(name);
    let present = path.is_file();
    let mut version = None;
    if present {
        version = file_version(&path);
    }
    format!(
        "{{\"name\":{},\"present\":{},\"version\":{}}}",
        js(name),
        present,
        jopt(version)
    )
}

fn file_version(path: &PathBuf) -> Option<String> {
    unsafe {
        let w = wide(&path.to_string_lossy());
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeExW(0, w.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoExW(0, w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) == 0 {
            return None;
        }
        let mut info: *mut c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if VerQueryValueW(
            buf.as_ptr() as *const c_void,
            wide("\\").as_ptr(),
            &mut info,
            &mut len,
        ) == 0
            || info.is_null()
        {
            return None;
        }
        // VS_FIXEDFILEINFO: dwSignature at 0, dwFileVersionMS at +8, LS at +12.
        let ms = *(info as *const u32).add(2);
        let ls = *(info as *const u32).add(3);
        Some(format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xffff,
            ls >> 16,
            ls & 0xffff
        ))
    }
}

/// Read a REG_SZ/REG_DWORD value from an HKLM key (read-only).
fn reg_read(root: HKEY, sub: &str, value: &str) -> Option<String> {
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, wide(sub).as_ptr(), 0, KEY_READ, &mut key) != ERROR_SUCCESS {
            return None;
        }
        let mut ty = 0u32;
        let mut len = 0u32;
        let rc = RegQueryValueExW(
            key,
            wide(value).as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            std::ptr::null_mut(),
            &mut len,
        );
        if rc != ERROR_SUCCESS {
            RegCloseKey(key);
            return None;
        }
        let out = if ty == 4 {
            // REG_DWORD
            let mut v = 0u32;
            let mut l = 4u32;
            if RegQueryValueExW(
                key,
                wide(value).as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut v as *mut u32 as *mut u8,
                &mut l,
            ) == ERROR_SUCCESS
            {
                Some(v.to_string())
            } else {
                None
            }
        } else {
            let mut buf = vec![0u8; len as usize + 2];
            let rc = RegQueryValueExW(
                key,
                wide(value).as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            );
            if rc != ERROR_SUCCESS {
                None
            } else {
                let units: Vec<u16> = buf[..len as usize]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                Some(
                    String::from_utf16_lossy(&units)
                        .trim_end_matches('\0')
                        .to_string(),
                )
            }
        };
        RegCloseKey(key);
        out
    }
}

fn reg_dword(root: HKEY, sub: &str, value: &str) -> Option<u32> {
    reg_read(root, sub, value).and_then(|s| s.parse().ok())
}

/// Service registration facts (registry presence only — never SCM control).
fn service_fact(name: &str) -> String {
    let sub = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    let start = reg_dword(HKLM, &sub, "Start");
    let image = reg_read(HKLM, &sub, "ImagePath");
    let dll = reg_read(HKLM, &format!(r"{sub}\Parameters"), "ServiceDll");
    format!(
        "{{\"name\":{},\"registered\":{},\"start\":{},\"image\":{},\"service_dll\":{}}}",
        js(name),
        start.is_some(),
        start
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".into()),
        jopt(image),
        jopt(dll)
    )
}

/// Token facts for the current process — also how a sandboxed child
/// reports what environment it actually landed in.
fn token_facts() -> String {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return "{\"queried\":false}".into();
        }
        let q = |class: u32| -> Option<Vec<u8>> {
            let mut len = 0u32;
            GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len);
            if len == 0 {
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            if GetTokenInformation(token, class, buf.as_mut_ptr() as *mut c_void, len, &mut len)
                == 0
            {
                return None;
            }
            Some(buf)
        };
        let u32_at = |class: u32| q(class).map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()));
        // TokenInformationClass values.
        let is_ac = u32_at(29).map(|v| v != 0); // TokenIsAppContainer
        let session_id = u32_at(12); // TokenSessionId
        let elev_type = u32_at(18); // TokenElevationType
        let elevated = u32_at(20).map(|v| v != 0); // TokenIsElevated
                                                   // TokenIntegrityLevel (25) -> TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES };
                                                   // the integrity level is the SID's last subauthority.
        let integrity_level = q(25).and_then(|b| {
            if b.len() < 12 {
                return None;
            }
            let sid = usize::from_le_bytes(b[..8].try_into().unwrap()) as *const u8;
            let count = *sid.add(1) as usize;
            if count < 1 || sid.is_null() {
                return None;
            }
            let off = 8 + 4 * (count - 1);
            Some(u32::from_le_bytes(
                std::slice::from_raw_parts(sid.add(off), 4)
                    .try_into()
                    .unwrap(),
            ))
        });
        // TokenAppContainerSid (31) -> TOKEN_APPCONTAINER_INFORMATION { psid }.
        let ac_sid = q(31).and_then(|b| {
            if b.len() < 8 {
                return None;
            }
            let sid = usize::from_le_bytes(b[..8].try_into().unwrap()) as PSID;
            sid_str(sid)
        });
        CloseHandle(token);
        format!(
            "{{\"queried\":true,\"is_appcontainer\":{},\"session_id\":{},\"elevation_type\":{},\"elevated\":{},\"integrity_level\":{},\"appcontainer_sid\":{}}}",
            is_ac.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            session_id.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            elev_type.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            elevated.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            integrity_level.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            jopt(ac_sid)
        )
    }
}

fn sid_str(sid: PSID) -> Option<String> {
    unsafe {
        if sid.is_null() {
            return None;
        }
        let mut out: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *out.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
        LocalFree(out as *mut c_void);
        Some(s)
    }
}

// ─── mode: facts ────────────────────────────────────────────────────────────

fn mode_facts() -> String {
    unsafe {
        let mut vi = OsVersionInfoW {
            size: std::mem::size_of::<OsVersionInfoW>() as u32,
            ..std::mem::zeroed()
        };
        let _ = RtlGetVersion(&mut vi);
        let ubr = reg_dword(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
        let display = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DisplayVersion",
        );
        let edition = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "EditionID",
        );
        let product = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        );

        let files = [
            "processmodel.dll",
            "IsoSessionApp.dll",
            "IsoSessionCli.exe",
            "IsoSessionClient.dll",
            "IsoSessionServer.dll",
            "IsoSessionProxyStub.dll",
            "bfscfg.exe",
            "CheckNetIsolation.exe",
            "vmwp.exe",
            "wsb.exe",
            "wslc.exe",
            "hsnproxy.dll",
            "computestorage.dll",
            "appisolation.dll",
        ];
        let files_json = files
            .iter()
            .map(|f| file_fact(f))
            .collect::<Vec<_>>()
            .join(",");
        let services = ["IsoEnvBroker", "IsolationSession", "bfssvc", "appisolation"];
        let services_json = services
            .iter()
            .map(|s| service_fact(s))
            .collect::<Vec<_>>()
            .join(",");

        let apiset = |name: &str| -> String {
            let cname = std::ffi::CString::new(name).unwrap();
            let present = IsApiSetImplemented(cname.as_ptr() as *const u8);
            format!("{{\"name\":{},\"implemented\":{}}}", js(name), present != 0)
        };
        let apisets = [
            "api-win-appmodel-processmodel~securityenvironment",
            "api-win-appmodel-processmodel~learningmodetrace",
            "api-win-app-isolation-l1-1-0",
        ];
        let apiset_json = apisets
            .iter()
            .map(|a| apiset(a))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"mode\":\"facts\",\"host\":{{\"os\":{{\"major\":{},\"minor\":{},\"build\":{},\"ubr\":{}}},\"display_version\":{},\"edition\":{},\"product\":{},\"arch\":{}}},\"token\":{},\"files\":[{}],\"services\":[{}],\"api_sets\":[{}]}}",
            vi.major,
            vi.minor,
            vi.build,
            ubr.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            jopt(display),
            jopt(edition),
            jopt(product),
            js(std::env::consts::ARCH),
            token_facts(),
            files_json,
            services_json,
            apiset_json
        )
    }
}

// ─── mode: contracts ────────────────────────────────────────────────────────

const PSEC_EXPORTS: &[&str] = &[
    "CreateProcessSecurityEnvironment",
    "QueryProcessSecurityEnvironmentSupport",
    "IsProcessSecurityEnvironmentVersionSupported",
    "CloseProcessSecurityEnvironment",
    "StartLearningModeTrace",
    "StopLearningModeTrace",
    "CloseLearningModeTrace",
    "CancelProcessSecurityEnvironmentTerminateOnClose",
    "SbeGetSecurityEnvironmentAppContainerSid",
    "Experimental_CompileSandboxSpecificationInternal",
    "Experimental_QuerySandboxSupport",
    "Experimental_CreateProcessInSandbox",
];

fn load_system_dll(name: &str) -> HANDLE {
    unsafe {
        LoadLibraryExW(
            wide(name).as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
}

fn export_addr(dll: HANDLE, name: &str) -> *mut c_void {
    unsafe {
        let c = std::ffi::CString::new(name).unwrap();
        GetProcAddress(dll, c.as_ptr() as *const u8)
    }
}

fn contracts_psec() -> String {
    unsafe {
        let mut out = String::from("{\"api_set\":");
        let cname =
            std::ffi::CString::new("api-win-appmodel-processmodel~securityenvironment").unwrap();
        out.push_str(&format!(
            "{}",
            IsApiSetImplemented(cname.as_ptr() as *const u8) != 0
        ));
        let lm = std::ffi::CString::new("api-win-appmodel-processmodel~learningmodetrace").unwrap();
        out.push_str(&format!(
            ",\"api_set_learning_mode\":{}",
            IsApiSetImplemented(lm.as_ptr() as *const u8) != 0
        ));

        let dll = load_system_dll("processmodel.dll");
        out.push_str(&format!(",\"dll_loaded\":{}", !dll.is_null()));
        if dll.is_null() {
            out.push('}');
            return out;
        }
        let exports = PSEC_EXPORTS
            .iter()
            .map(|e| format!("\"{}\":{}", e, !export_addr(dll, e).is_null()))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(",\"exports\":{{{exports}}}"));

        // Support-flags query — a real API answer, not inference.
        let qname = std::ffi::CString::new("QueryProcessSecurityEnvironmentSupport").unwrap();
        let qp = GetProcAddress(dll, qname.as_ptr() as *const u8);
        if !qp.is_null() {
            let q: unsafe extern "system" fn(*mut u64) -> HRESULT = std::mem::transmute(qp);
            let mut flags: u64 = 0;
            let hr = q(&mut flags);
            out.push_str(&format!(
                ",\"query_support\":{{\"hr\":\"{}\",\"flags\":\"0x{flags:016x}\"}}",
                hr_str(hr)
            ));
        }
        // Version query for majors 1 and 2 — MXC calls
        // (major, available*, minor*): supported iff returned minor >= ask.
        let vname = std::ffi::CString::new("IsProcessSecurityEnvironmentVersionSupported").unwrap();
        let vp = GetProcAddress(dll, vname.as_ptr() as *const u8);
        if !vp.is_null() {
            let v: unsafe extern "system" fn(u32, *mut u8, *mut u32) -> HRESULT =
                std::mem::transmute(vp);
            out.push_str(",\"version_support\":[");
            let mut first = true;
            for major in [1u32, 2] {
                let mut avail: u8 = 0;
                let mut minor: u32 = 0;
                let hr = v(major, &mut avail, &mut minor);
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&format!(
                    "{{\"major\":{major},\"hr\":\"{}\",\"available\":{},\"minor\":{minor}}}",
                    hr_str(hr),
                    avail != 0
                ));
            }
            out.push(']');
        }
        // Bounded create probes — malformed/empty specs prove the RPC
        // endpoint and schema check are live without creating an env.
        let cname2 = std::ffi::CString::new("CreateProcessSecurityEnvironment").unwrap();
        let cp = GetProcAddress(dll, cname2.as_ptr() as *const u8);
        if !cp.is_null() {
            let c: unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> HRESULT =
                std::mem::transmute(cp);
            out.push_str(",\"create_probes\":[");
            let specs: [(&str, Vec<u8>); 2] =
                [("empty", Vec::new()), ("magic-only", b"PSEC".to_vec())];
            let mut first = true;
            for (label, spec) in specs {
                let mut env: HANDLE = std::ptr::null_mut();
                let hr = c(
                    spec.as_ptr() as *const c_void,
                    spec.len() as u32,
                    0,
                    &mut env,
                );
                if !first {
                    out.push(',');
                }
                first = false;
                let mut closed = false;
                if !env.is_null() {
                    let clname = std::ffi::CString::new("CloseProcessSecurityEnvironment").unwrap();
                    let clp = GetProcAddress(dll, clname.as_ptr() as *const u8);
                    if !clp.is_null() {
                        let cl: unsafe extern "system" fn(HANDLE) = std::mem::transmute(clp);
                        cl(env);
                        closed = true;
                    }
                }
                out.push_str(&format!(
                    "{{\"spec\":\"{label}\",\"hr\":\"{}\",\"env_returned\":{},\"closed\":{closed}}}",
                    hr_str(hr),
                    !env.is_null()
                ));
            }
            out.push(']');
        }
        FreeLibrary(dll);
        out.push('}');
        out
    }
}

/// IActivationFactory IID {00000035-...-0046}.
const IACTIVATIONFACTORY_IID: [u8; 16] = [
    0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

fn hstring_to_string(hs: *mut c_void) -> Option<String> {
    unsafe {
        if hs.is_null() {
            return None;
        }
        let mut len = 0u32;
        let ptr = WindowsGetStringRawBuffer(hs, &mut len);
        if ptr.is_null() {
            return None;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            ptr,
            len as usize,
        )))
    }
}

fn activate_class(name: &str) -> String {
    unsafe {
        let w = wide(name);
        let mut hs: *mut c_void = std::ptr::null_mut();
        let hr = WindowsCreateString(w.as_ptr(), (w.len() - 1) as u32, &mut hs);
        if hr != 0 {
            return format!(
                "{{\"class\":{},\"activation_hr\":\"{}\"}}",
                js(name),
                hr_str(hr)
            );
        }
        let mut factory: *mut c_void = std::ptr::null_mut();
        let hr = RoGetActivationFactory(
            hs,
            IACTIVATIONFACTORY_IID.as_ptr() as *const c_void,
            &mut factory,
        );
        if hr != 0 || factory.is_null() {
            WindowsDeleteString(hs);
            return format!(
                "{{\"class\":{},\"activation_hr\":\"{}\",\"activated\":false}}",
                js(name),
                hr_str(hr)
            );
        }
        // IActivationFactory::ActivateInstance = vtbl[6].
        let vtbl = *(factory as *const *const *const c_void);
        let activate: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT =
            std::mem::transmute(*vtbl.add(6));
        let mut obj: *mut c_void = std::ptr::null_mut();
        let ahr = activate(factory, &mut obj);
        let mut iid_count = 0u32;
        let mut runtime_class = String::new();
        if !obj.is_null() {
            let ovtbl = *(obj as *const *const *const c_void);
            let getiids: unsafe extern "system" fn(
                *mut c_void,
                *mut u32,
                *mut *mut c_void,
            ) -> HRESULT = std::mem::transmute(*ovtbl.add(3));
            let getname: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT =
                std::mem::transmute(*ovtbl.add(4));
            let mut iids: *mut c_void = std::ptr::null_mut();
            let _ = getiids(obj, &mut iid_count, &mut iids);
            if !iids.is_null() {
                CoTaskMemFree(iids);
            }
            let mut rcs: *mut c_void = std::ptr::null_mut();
            if getname(obj, &mut rcs) == 0 {
                runtime_class = hstring_to_string(rcs).unwrap_or_default();
                WindowsDeleteString(rcs);
            }
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(*ovtbl.add(2));
            release(obj);
        }
        let fvtbl = *(factory as *const *const *const c_void);
        let release: unsafe extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(*fvtbl.add(2));
        release(factory);
        WindowsDeleteString(hs);
        format!(
            "{{\"class\":{},\"activation_hr\":\"{}\",\"activated\":{},\"activate_hr\":\"{}\",\"runtime_class\":{},\"iid_count\":{}}}",
            js(name),
            hr_str(hr),
            !obj.is_null(),
            hr_str(ahr),
            js(&runtime_class),
            iid_count
        )
    }
}

fn contracts_isosession() -> String {
    unsafe {
        let mut out = String::from("{\"dlls\":{");
        for (i, d) in [
            "IsoSessionApp.dll",
            "IsoSessionClient.dll",
            "IsoSessionServer.dll",
        ]
        .iter()
        .enumerate()
        {
            let h = load_system_dll(d);
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{d}\":{{\"loaded\":{}", !h.is_null()));
            if !h.is_null() {
                for (j, e) in [
                    "DllGetActivationFactory",
                    "IsIsoSessionSupported",
                    "IsoSessionClientQueryLocalAgentUserSupport",
                ]
                .iter()
                .enumerate()
                {
                    let _ = j;
                    out.push_str(&format!(
                        ",\"export_{}\":{}",
                        e,
                        !export_addr(h, e).is_null()
                    ));
                }
                FreeLibrary(h);
            }
            out.push('}');
        }
        out.push_str("},\"classes\":[");
        let hr = RoInitialize(0);
        out.push_str(&format!("{{\"roinitialize_hr\":\"{}\"}},", hr_str(hr)));
        for (i, cls) in [
            "Windows.AI.IsolationSession.IsoSessionOps",
            "Windows.AI.IsolationSession.Preview.IsoSessionOps",
            "Windows.AI.IsolationSession.IsoStationOps",
            // control: an unregistered name must fail as REGDB_E_CLASSNOTREG,
            // proving activation success above is real and not indiscriminate.
            "Windows.AI.IsolationSession.NotARealClass",
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&activate_class(cls));
        }
        out.push(']');
        CoUninitialize();
        out.push('}');
        out
    }
}

fn mode_contracts() -> String {
    let psec = contracts_psec();
    let iso = contracts_isosession();
    // Win32 app isolation: packaging-level contract — the only honest
    // host-tier signals are preview service/registry artifacts.
    let svc = service_fact("appisolation");
    let reg = reg_read(HKLM, r"SOFTWARE\Microsoft\Windows\AppIsolation", "Enabled");
    format!(
        "{{\"mode\":\"contracts\",\"psec\":{},\"isolation_session\":{},\"win32_app_isolation\":{{\"service\":{},\"reg_enabled\":{},\"note\":\"packaging-level contract; host signal is preview-tier only\"}}}}",
        psec, iso, svc, jopt(reg)
    )
}

// ─── mode: attempts ─────────────────────────────────────────────────────────

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
fn mode_attempts(args: &[String]) -> String {
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

// ─── shared spawn plumbing (ac-run / psec-run) ──────────────────────────────

struct SpawnOut {
    ok: bool,
    detail: String,
    child_json: String,
    child_pid: u32,
    gc_pid: Option<u32>,
    /// `Some(true)` when a spawned grandchild was dead once the job
    /// handle closed — the descendant-teardown evidence.
    gc_killed: Option<bool>,
    create_err: u32,
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
unsafe fn spawn_wrapped(
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
fn attempts_args(gc_exe: Option<&PathBuf>, net_allow: Option<String>) -> Vec<String> {
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
fn split_image(args: &[String]) -> (Option<PathBuf>, Vec<String>) {
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
fn bind_loopback() -> Option<(std::net::TcpListener, String)> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let addr = l.local_addr().ok()?.to_string();
    Some((l, addr))
}

/// A child's stdout is embedded verbatim only when it is one complete
/// JSON object — a sandboxed child that panics mid-emit (LPAC
/// `WSAStartup`, …) must not corrupt the parent's report. Otherwise the
/// raw text goes to `child_stdout` and `child` stays `null`.
fn child_json_or_null(raw: &str) -> String {
    let t = raw.trim().trim_start_matches('\u{feff}');
    if t.starts_with('{') && t.ends_with('}') {
        t.to_string()
    } else {
        "null".into()
    }
}

/// `,"child_stdout":"..."` for the non-JSON child case — the evidence of
/// *why* the child report failed belongs in the record, not discarded.
fn child_stdout_field(raw: &str) -> String {
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

// ─── mode: ac-run ───────────────────────────────────────────────────────────

struct Grant {
    path: PathBuf,
    mask: u32,
    applied: bool,
    restored: bool,
    error: Option<u32>,
    backup_sd: *mut c_void,
    backup_dacl: *mut c_void,
}

fn apply_dacl_grant(path: &PathBuf, sid: PSID, mask: u32) -> Result<Grant, u32> {
    unsafe {
        let w = wide(&path.to_string_lossy());
        let mut old_dacl: *mut c_void = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(rc);
        }
        let mut ea = ExplicitAccessW {
            access_permissions: mask,
            access_mode: SET_ACCESS,
            inheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            trustee_multiple: std::ptr::null_mut(),
            trustee_op: 0, // NO_MULTIPLE_TRUSTEE
            trustee_form: TRUSTEE_IS_SID,
            trustee_type: TRUSTEE_IS_UNKNOWN,
            trustee_name: sid,
        };
        let mut new_dacl: *mut c_void = std::ptr::null_mut();
        let rc = SetEntriesInAclW(1, &mut ea, old_dacl, &mut new_dacl);
        if rc != ERROR_SUCCESS {
            LocalFree(sd);
            return Err(rc);
        }
        let mut wmut = w.clone();
        let rc = SetNamedSecurityInfoW(
            wmut.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl);
        if rc != ERROR_SUCCESS {
            LocalFree(sd);
            return Err(rc);
        }
        Ok(Grant {
            path: path.clone(),
            mask,
            applied: true,
            restored: false,
            error: None,
            backup_sd: sd,
            backup_dacl: old_dacl,
        })
    }
}

fn restore_grant(g: &mut Grant) {
    unsafe {
        if !g.backup_sd.is_null() {
            let mut w = wide(&g.path.to_string_lossy());
            let rc = SetNamedSecurityInfoW(
                w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                g.backup_dacl,
                std::ptr::null_mut(),
            );
            g.restored = rc == ERROR_SUCCESS;
            LocalFree(g.backup_sd);
            g.backup_sd = std::ptr::null_mut();
        }
    }
}

fn mode_ac_run(args: &[String]) -> String {
    unsafe {
        let lpac = args.iter().any(|a| a == "--lpac");
        let net = args.iter().any(|a| a == "--net");
        let name = format!("mcp-writ-pr30-{:08x}", GetCurrentProcessId());
        let mut sid: PSID = std::ptr::null_mut();
        let hr = CreateAppContainerProfile(
            wide(&name).as_ptr(),
            wide(&name).as_ptr(),
            wide("PR-30 probe profile").as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut sid,
        );
        if hr != 0 {
            // Profile may exist from a killed earlier run — delete+retry once.
            let _ = DeleteAppContainerProfile(wide(&name).as_ptr());
            let hr2 = CreateAppContainerProfile(
                wide(&name).as_ptr(),
                wide(&name).as_ptr(),
                wide("PR-30 probe profile").as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut sid,
            );
            if hr2 != 0 {
                return format!(
                    "{{\"mode\":\"ac-run\",\"profile_created\":false,\"create_hr\":\"{}\"}}",
                    hr_str(hr2)
                );
            }
        }
        let mut cleanup_error = false;

        // Optional internetClient capability (S-1-15-3-1) — network allow
        // contrast leg, mirroring the product's capability SID path.
        // SECURITY_CAPABILITIES.Capabilities is a SID_AND_ATTRIBUTES[]
        // ({Sid ptr, Attributes u32}), not a raw PSID array.
        let mut cap_sids: Vec<PSID> = Vec::new();
        if net {
            let mut csid: PSID = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide("S-1-15-3-1").as_ptr(), &mut csid) != 0 {
                cap_sids.push(csid);
            }
        }
        let cap_attrs: Vec<(usize, u32)> = cap_sids.iter().map(|s| (*s as usize, 0u32)).collect();

        // DACL grants on caller-created dirs only — backup before change,
        // restore after run, owner-tracked exactly like the product path.
        let mut grants: Vec<Grant> = Vec::new();
        for (env_var, mask) in [
            ("WINISO_RO_DIR", GENERIC_READ_EXECUTE),
            ("WINISO_RW_DIR", GENERIC_ALL),
        ] {
            if let Ok(p) = std::env::var(env_var) {
                let dir = PathBuf::from(p);
                match apply_dacl_grant(&dir, sid, mask) {
                    Ok(g) => grants.push(g),
                    Err(rc) => grants.push(Grant {
                        path: dir,
                        mask,
                        applied: false,
                        restored: false,
                        error: Some(rc),
                        backup_sd: std::ptr::null_mut(),
                        backup_dacl: std::ptr::null_mut(),
                    }),
                }
            }
        }

        // Attributes: security capabilities + optional LPAC opt-out;
        // spawn_wrapped adds the handle list itself.
        let caps = SecurityCapabilities {
            appcontainer_sid: sid,
            capabilities: if cap_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                cap_attrs.as_ptr() as *mut c_void
            },
            capability_count: cap_attrs.len() as u32,
            reserved: 0,
        };
        let opt_out: u32 = 1;
        let mut attrs: Vec<(usize, *const c_void, usize)> = vec![(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &caps as *const _ as *const c_void,
            std::mem::size_of::<SecurityCapabilities>(),
        )];
        if lpac {
            attrs.push((
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &opt_out as *const _ as *const c_void,
                4,
            ));
        }

        // `--image <exe> <argv...>` spawns an external binary under the
        // same AppContainer token + DACL grants — the Node/Python launch
        // leg (real-world launch conditions vs the probe's own exe).
        let (image, image_argv) = split_image(args);

        // Give the sandboxed child an executable it can actually run for
        // the grandchild leg: an exe copy inside the RW grant (test-owned
        // path; the repo dir itself is never ACL-touched). The context
        // travels on argv — a security-environment child is not promised
        // the parent's env block.
        let mut gc_note = String::new();
        let mut gc_exe_arg: Option<PathBuf> = None;
        if image.is_none() {
            if let Ok(rw) = std::env::var("WINISO_RW_DIR") {
                let exe = std::env::current_exe().unwrap();
                let copy = PathBuf::from(&rw).join("mcp-writ-pr30-child.exe");
                match std::fs::copy(&exe, &copy) {
                    Ok(_) => {
                        gc_exe_arg = Some(copy.clone());
                        gc_note = format!("gc_exe={}", copy.to_string_lossy());
                    }
                    Err(e) => {
                        gc_note = format!("gc exe copy failed: {e}");
                    }
                }
            }
        }
        // Loopback listener for the `net_connect_allow` leg — whether a
        // sandboxed child can reach it (and how the denied leg fails)
        // is the capability evidence, not just "is a socket possible".
        let listener = bind_loopback();
        let child_args = if image.is_some() {
            image_argv
        } else {
            attempts_args(
                gc_exe_arg.as_ref(),
                listener.as_ref().map(|(_, a)| a.clone()),
            )
        };
        let spawn_image = image.clone().unwrap_or_else(|| std::env::current_exe().unwrap());
        let mut spawn = spawn_wrapped(&spawn_image, &child_args, &attrs);
        drop(listener);
        if !gc_note.is_empty() {
            spawn.detail.push_str(&format!("; {gc_note}"));
        }

        for g in grants.iter_mut() {
            restore_grant(g);
        }
        let dhr = DeleteAppContainerProfile(wide(&name).as_ptr());
        for csid in cap_sids {
            FreeSid(csid);
        }
        if !sid.is_null() {
            FreeSid(sid);
        }
        if dhr != 0 {
            cleanup_error = true;
        }
        let grants_json = grants
            .iter()
            .map(|g| {
                format!(
                    "{{\"path\":{},\"mask\":\"0x{:08x}\",\"applied\":{},\"restored\":{},\"error\":{}}}",
                    js(&g.path.to_string_lossy()),
                    g.mask,
                    g.applied,
                    g.restored,
                    g.error.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let child_json = child_json_or_null(&spawn.child_json);
        format!(
            "{{\"mode\":\"ac-run\",\"profile_created\":true,\"lpac\":{},\"net_capability\":{},\"child_image\":{},\"grants\":[{}],\"spawn_ok\":{},\"spawn_detail\":{},\"child_pid\":{},\"gc_pid\":{},\"gc_killed\":{},\"child\":{},\"profile_deleted\":{},\"cleanup_error\":{}{}}}",
            lpac,
            net,
            image
                .as_ref()
                .map(|p| js(&p.to_string_lossy()))
                .unwrap_or_else(|| "null".into()),
            grants_json,
            spawn.ok,
            js(&spawn.detail),
            spawn.child_pid,
            spawn.gc_pid.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            spawn.gc_killed.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            child_json,
            dhr == 0,
            cleanup_error,
            child_stdout_field(&spawn.child_json)
        )
    }
}

// ─── PSEC flatbuffer spec ───────────────────────────────────────────────────

/// Minimal FlatBuffers writer for the public
/// `external/windows-sdk/ProcessSecurityEnvironment.fbs` schema
/// (`file_identifier "PSEC"`, `root_type ProcessSecurityEnvironment`).
///
/// The wire-format rule that matters here: a `uoffset` field must point
/// *forward* — to a higher buffer position than the field slot — so a
/// table's referenced children are laid out after the table itself
/// (the vtable still precedes its table; that offset is the signed
/// `soffset`). This builder therefore writes parents first and patches
/// reference slots once each child's position is known.
struct Fb {
    buf: Vec<u8>,
}

impl Fb {
    /// `with_ident` writes the schema's `file_identifier "PSEC"` at
    /// bytes 4..8; without it the root uoffset leads the buffer.
    fn new(with_ident: bool) -> Self {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(&0u32.to_le_bytes());
        if with_ident {
            buf.extend_from_slice(b"PSEC");
        }
        Fb { buf }
    }

    fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    fn pos(&self) -> u32 {
        self.buf.len() as u32
    }

    fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// The spec nodes this probe encodes.
enum SpecNode {
    Str(String),
    StrVec(Vec<String>),
    /// Vector of offsets to tables (e.g. `[EndpointRule]`).
    TabVec(Vec<SpecNode>),
    Table {
        max_slot: usize,
        fields: Vec<(usize, FieldV)>,
    },
}

enum FieldV {
    U8(u8),
    U16(u16),
    /// Inline `SchemaVersion` struct: {major u16, minor u16}.
    Ver(u16, u16),
    Ref(Box<SpecNode>),
}

/// Write `node` at the buffer end; children of Ref fields follow
/// immediately so every uoffset points forward. Returns the node pos.
fn write_node(fb: &mut Fb, node: &SpecNode) -> u32 {
    match node {
        SpecNode::Str(s) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
            fb.buf.extend_from_slice(s.as_bytes());
            fb.buf.push(0);
            pos
        }
        SpecNode::StrVec(items) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf
                .extend_from_slice(&(items.len() as u32).to_le_bytes());
            let mut slots = Vec::with_capacity(items.len());
            for _ in items {
                slots.push(fb.pos() as usize);
                fb.buf.extend_from_slice(&0u32.to_le_bytes());
            }
            // Elements forward-reference the strings written right after.
            for (slot, s) in slots.iter().zip(items.iter()) {
                let sp = write_node(fb, &SpecNode::Str(s.clone()));
                fb.patch_u32(*slot, sp - *slot as u32);
            }
            pos
        }
        SpecNode::TabVec(items) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf
                .extend_from_slice(&(items.len() as u32).to_le_bytes());
            let mut slots = Vec::with_capacity(items.len());
            for _ in items {
                slots.push(fb.pos() as usize);
                fb.buf.extend_from_slice(&0u32.to_le_bytes());
            }
            for (slot, s) in slots.iter().zip(items.iter()) {
                let sp = write_node(fb, s);
                fb.patch_u32(*slot, sp - *slot as u32);
            }
            pos
        }
        SpecNode::Table { max_slot, fields } => {
            // Field layout: 4-aligned packing after the i32 soffset.
            let mut offs: Vec<u16> = Vec::with_capacity(fields.len());
            let mut cursor: usize = 4;
            for (_slot, f) in fields {
                while cursor % 4 != 0 {
                    cursor += 1;
                }
                offs.push(cursor as u16);
                cursor += match f {
                    FieldV::U8(_) => 1,
                    FieldV::U16(_) => 2,
                    FieldV::Ver(..) | FieldV::Ref(_) => 4,
                };
            }
            let table_size = ((cursor + 3) & !3) as u16;
            let vlen = (4 + 2 * (max_slot + 1)) as u16;

            // vtable first (must precede the table in the buffer).
            fb.align(4);
            let vpos = fb.pos() as usize;
            fb.buf.extend_from_slice(&vlen.to_le_bytes());
            fb.buf.extend_from_slice(&table_size.to_le_bytes());
            for s in 0..=*max_slot {
                let off = fields
                    .iter()
                    .zip(offs.iter())
                    .find(|((slot, _), _)| *slot == s)
                    .map(|(_, o)| *o)
                    .unwrap_or(0u16);
                fb.buf.extend_from_slice(&off.to_le_bytes());
            }
            fb.align(4);
            let tpos = fb.pos() as usize;
            fb.buf.resize(tpos + table_size as usize, 0);
            let soffset = (tpos - vpos) as i32;
            fb.buf[tpos..tpos + 4].copy_from_slice(&soffset.to_le_bytes());
            // Scalars in place; each Ref child is written right after the
            // table (forward uoffset) and its slot patched.
            let mut ref_fields: Vec<(usize, &SpecNode)> = Vec::new();
            for ((_slot, f), off) in fields.iter().zip(offs.iter()) {
                let at = tpos + *off as usize;
                match f {
                    FieldV::U8(v) => fb.buf[at] = *v,
                    FieldV::U16(v) => {
                        fb.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
                    }
                    FieldV::Ver(a, b) => {
                        fb.buf[at..at + 2].copy_from_slice(&a.to_le_bytes());
                        fb.buf[at + 2..at + 4].copy_from_slice(&b.to_le_bytes());
                    }
                    FieldV::Ref(child) => ref_fields.push((at, child)),
                }
            }
            for (at, child) in ref_fields {
                let cp = write_node(fb, child);
                fb.patch_u32(at, cp - at as u32);
            }
            tpos as u32
        }
    }
}

/// Root the buffer at `node` and return the finished bytes.
fn fb_finish(mut fb: Fb, node: &SpecNode) -> Vec<u8> {
    let root = write_node(&mut fb, node);
    fb.patch_u32(0, root);
    fb.buf
}

/// Network posture encoded into `network_policy` (root slot 7).
enum NetSpec {
    /// No network_policy field at all.
    None,
    /// `egress = { default_action: deny }` — the deny byte is written
    /// explicitly so a refused connect is on the wire, not a schema
    /// default.
    DenyAll,
    /// `egress = { default_action: deny, allow: [{destinations:
    /// [{subnet: {addr, prefix 32}}], ports: [{tcp, port}]}] }` — a
    /// pinned destination/port rule so an allowed connect and a denied
    /// connect can be told apart.
    AllowOnly { addr: String, port: u16 },
}

fn net_policy_node(spec: &NetSpec) -> SpecNode {
    let mut egress_fields: Vec<(usize, FieldV)> = vec![(0, FieldV::U8(0))];
    if let NetSpec::AllowOnly { addr, port } = spec {
        // IpSubnet{ address, prefix_length }
        let subnet = SpecNode::Table {
            max_slot: 1,
            fields: vec![
                (0, FieldV::Ref(Box::new(SpecNode::Str(addr.clone())))),
                (1, FieldV::U8(32)),
            ],
        };
        // DestinationRule{ subnet }
        let dest = SpecNode::Table {
            max_slot: 1,
            fields: vec![(0, FieldV::Ref(Box::new(subnet)))],
        };
        // PortRule{ protocol: tcp(1), port }
        let port_rule = SpecNode::Table {
            max_slot: 2,
            fields: vec![(0, FieldV::U8(1)), (1, FieldV::U16(*port))],
        };
        // EndpointRule{ destinations: [..], ports: [..] }
        let rule = SpecNode::Table {
            max_slot: 1,
            fields: vec![
                (0, FieldV::Ref(Box::new(SpecNode::TabVec(vec![dest])))),
                (1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![port_rule])))),
            ],
        };
        // EndpointPolicy{ default_action: deny, allow: [rule] }
        egress_fields.push((1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![rule])))));
    }
    let egress = SpecNode::Table {
        max_slot: 2,
        fields: egress_fields,
    };
    // NetworkPolicy{ egress } — egress is vtable slot 1.
    SpecNode::Table {
        max_slot: 3,
        fields: vec![(1, FieldV::Ref(Box::new(egress)))],
    }
}

/// Build a PSEC spec (`file_identifier "PSEC"`, schema v1.0).
fn psec_spec(ro: &[String], rw: &[String], deny: &[String], net: &NetSpec, ident: bool) -> Vec<u8> {
    let mut fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(1, 0))];
    if !rw.is_empty() {
        // fs_read_write — slot 4.
        fields.push((4, FieldV::Ref(Box::new(SpecNode::StrVec(rw.to_vec())))));
    }
    if !ro.is_empty() {
        // fs_read_only — slot 5.
        fields.push((5, FieldV::Ref(Box::new(SpecNode::StrVec(ro.to_vec())))));
    }
    if !deny.is_empty() {
        // fs_deny — slot 6.
        fields.push((6, FieldV::Ref(Box::new(SpecNode::StrVec(deny.to_vec())))));
    }
    if !matches!(net, NetSpec::None) {
        fields.push((7, FieldV::Ref(Box::new(net_policy_node(net)))));
    }
    let root = SpecNode::Table {
        max_slot: 8,
        fields,
    };
    fb_finish(Fb::new(ident), &root)
}

/// Bare-bones spec: version only (+ optional ident).
fn psec_spec_minimal(ident: bool, minor: u16) -> Vec<u8> {
    let root = SpecNode::Table {
        max_slot: 8,
        fields: vec![(0, FieldV::Ver(1, minor))],
    };
    fb_finish(Fb::new(ident), &root)
}

fn mode_psec_run(args: &[String]) -> String {
    unsafe {
        let mut ro: Vec<String> = Vec::new();
        let mut rw: Vec<String> = Vec::new();
        let mut deny: Vec<String> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--ro" => {
                    if let Some(v) = args.get(i + 1) {
                        ro.push(v.clone());
                    }
                    i += 2;
                }
                "--rw" => {
                    if let Some(v) = args.get(i + 1) {
                        rw.push(v.clone());
                    }
                    i += 2;
                }
                "--deny" => {
                    if let Some(v) = args.get(i + 1) {
                        deny.push(v.clone());
                    }
                    i += 2;
                }
                _ => i += 1,
            }
        }
        // Bind the allow-leg listener first so its port can be pinned in
        // the spec's egress rule — the allow/deny contrast then proves
        // destination+port granularity, not just "deny-all".
        let listener = bind_loopback();
        let allow_port = listener
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port());
        let net_spec = match allow_port {
            Some(p) => NetSpec::AllowOnly {
                addr: "127.0.0.1".into(),
                port: p,
            },
            None => NetSpec::DenyAll,
        };
        let spec = psec_spec(&ro, &rw, &deny, &net_spec, true);
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
        for (env_var, flag) in [
            ("WINISO_UNGRANTED_DIR", "--ungranted"),
            ("WINISO_NET_ADDR", "--net-deny"),
        ] {
            if let Ok(v) = std::env::var(env_var) {
                child_args.push(flag.into());
                child_args.push(v);
            }
        }
        if let Some((_, addr)) = &listener {
            child_args.push("--net-allow".into());
            child_args.push(addr.clone());
        }
        if let Some(p) = allow_port {
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
        format!(
            "{{\"mode\":\"psec-run\",\"spec_len\":{},\"spec_ok\":{},\"create_hr\":\"{}\",\"env_closed\":true,\"child_image\":{},\"spawn_ok\":{},\"spawn_detail\":{},\"child_pid\":{},\"gc_pid\":{},\"gc_killed\":{},\"child\":{}{}}}",
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

fn mode_psec_spec_test() -> String {
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

// ─── main ───────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("facts") => println!("{}", mode_facts()),
        Some("contracts") => println!("{}", mode_contracts()),
        Some("attempts") => println!("{}", mode_attempts(&args[1..])),
        Some("ac-run") => println!("{}", mode_ac_run(&args[1..])),
        Some("psec-run") => println!("{}", mode_psec_run(&args[1..])),
        Some("sleep") => {
            let ms: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
            unsafe { Sleep(ms) };
        }
        Some("psec-spec-test") => {
            // Bounded create-attempt ladder to isolate what the schema
            // check accepts — each HRESULT is recorded, never retried
            // as a guess. No environment is left open: every successful
            // create is closed immediately.
            println!("{}", mode_psec_spec_test());
        }
        Some("spec-file") => {
            // Write the minimal spec for offline inspection/debugging.
            let out = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "psec-spec.bin".into());
            let spec = psec_spec(
                &["C:\\ro".to_string()],
                &["C:\\rw".to_string()],
                &["C:\\deny".to_string()],
                &NetSpec::DenyAll,
                true,
            );
            let mut f = std::fs::File::create(&out).expect("create spec file");
            f.write_all(&spec).expect("write spec");
            println!(
                "{{\"mode\":\"spec-file\",\"path\":{},\"len\":{}}}",
                js(&out),
                spec.len()
            );
        }
        _ => {
            eprintln!("usage: winiso_probe facts|contracts|attempts [flags]|ac-run [--lpac] [--net]|psec-run [--ro D --rw D --deny P]|psec-spec-test|sleep <ms>|spec-file <out>");
            std::process::exit(2);
        }
    }
}
