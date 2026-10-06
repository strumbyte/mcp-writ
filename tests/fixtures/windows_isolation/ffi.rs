//! FFI surface for the winiso probe — raw-dylib imports only, no import
//! libs. Everything here is `pub(crate)`; each mode module imports the
//! symbols it drives.

use std::ffi::c_void;

pub(crate) type HANDLE = *mut c_void;
pub(crate) type HRESULT = i32;
pub(crate) type BOOL = i32;
pub(crate) type PSID = *mut c_void;
pub(crate) type HKEY = *mut c_void;

pub(crate) const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
pub(crate) const CREATE_SUSPENDED: u32 = 0x0000_0004;
pub(crate) const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub(crate) const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
pub(crate) const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
pub(crate) const WAIT_TIMEOUT: u32 = 0x102;
pub(crate) const WAIT_OBJECT_0: u32 = 0;
pub(crate) const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;
pub(crate) const TOKEN_QUERY: u32 = 0x0008;
pub(crate) const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
pub(crate) const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

// Proc-thread attribute ids (ProcThreadAttributeValue | PROC_THREAD_ATTRIBUTE_INPUT).
pub(crate) const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
pub(crate) const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
pub(crate) const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
pub(crate) const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 0x0002_0023;

pub(crate) const SE_FILE_OBJECT: u32 = 1;
pub(crate) const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
pub(crate) const SET_ACCESS: u32 = 2;
pub(crate) const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;
pub(crate) const TRUSTEE_IS_SID: u32 = 0;
pub(crate) const TRUSTEE_IS_UNKNOWN: u32 = 0;
pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;
/// GENERIC_READ (0x8000_0000) | GENERIC_EXECUTE (0x2000_0000).
pub(crate) const GENERIC_READ_EXECUTE: u32 = 0xA000_0000;

pub(crate) const KEY_READ: u32 = 0x0002_0019; // KEY_QUERY_VALUE|ENUMERATE|NOTIFY|READ_CONTROL-ish (STANDARD_RIGHTS_READ composite)
pub(crate) const HKLM: HKEY = 0x8000_0002usize as HKEY;
pub(crate) const HKCU: HKEY = 0x8000_0001usize as HKEY;
pub(crate) const ERROR_SUCCESS: u32 = 0;

#[repr(C)]
pub(crate) struct ProcessInformation {
    pub(crate) process: HANDLE,
    pub(crate) thread: HANDLE,
    pub(crate) process_id: u32,
    pub(crate) thread_id: u32,
}

#[repr(C)]
pub(crate) struct SecurityCapabilities {
    pub(crate) appcontainer_sid: PSID,
    pub(crate) capabilities: *mut c_void,
    pub(crate) capability_count: u32,
    pub(crate) reserved: u32,
}

#[repr(C)]
pub(crate) struct StartupInfoExW {
    pub(crate) cb: u32,
    pub(crate) reserved: *mut u16,
    pub(crate) desktop: *mut u16,
    pub(crate) title: *mut u16,
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) x_size: u32,
    pub(crate) y_size: u32,
    pub(crate) x_count: u32,
    pub(crate) y_count: u32,
    pub(crate) fill: u32,
    pub(crate) flags: u32,
    pub(crate) show_window: u16,
    pub(crate) reserved2: u16,
    pub(crate) reserved2_ptr: *mut u8,
    pub(crate) std_input: HANDLE,
    pub(crate) std_output: HANDLE,
    pub(crate) std_error: HANDLE,
    pub(crate) attr_list: *mut c_void,
}

/// SID_AND_ATTRIBUTES — the element type of
/// `SECURITY_CAPABILITIES.Capabilities`.
#[repr(C)]
pub(crate) struct SidAndAttributes {
    pub(crate) sid: PSID,
    pub(crate) attributes: u32,
}

#[repr(C)]
pub(crate) struct OsVersionInfoW {
    pub(crate) size: u32,
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) build: u32,
    pub(crate) platform: u32,
    pub(crate) csd: [u16; 128],
}

#[repr(C)]
pub(crate) struct ExplicitAccessW {
    pub(crate) access_permissions: u32,
    pub(crate) access_mode: u32,
    pub(crate) inheritance: u32,
    pub(crate) trustee_multiple: *mut c_void,
    pub(crate) trustee_op: u32,
    pub(crate) trustee_form: u32,
    pub(crate) trustee_type: u32,
    pub(crate) trustee_name: *mut c_void, // PSID when TRUSTEE_IS_SID
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn LoadLibraryExW(name: *const u16, file: HANDLE, flags: u32) -> HANDLE;
    pub(crate) fn GetProcAddress(module: HANDLE, name: *const u8) -> *mut c_void;
    pub(crate) fn FreeLibrary(m: HANDLE) -> BOOL;
    pub(crate) fn GetLastError() -> u32;
    pub(crate) fn GetCurrentProcess() -> HANDLE;
    pub(crate) fn GetCurrentProcessId() -> u32;
    pub(crate) fn CloseHandle(h: HANDLE) -> BOOL;
    pub(crate) fn ReadFile(
        h: HANDLE,
        buf: *mut u8,
        len: u32,
        read: *mut u32,
        ov: *mut c_void,
    ) -> BOOL;
    pub(crate) fn CreatePipe(
        read: *mut HANDLE,
        write: *mut HANDLE,
        sa: *const c_void,
        size: u32,
    ) -> BOOL;
    pub(crate) fn SetHandleInformation(h: HANDLE, mask: u32, flags: u32) -> BOOL;
    pub(crate) fn CreateProcessW(
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
    pub(crate) fn CreateJobObjectW(sa: *const c_void, name: *const u16) -> HANDLE;
    pub(crate) fn SetInformationJobObject(
        job: HANDLE,
        class: u32,
        info: *const c_void,
        len: u32,
    ) -> BOOL;
    pub(crate) fn AssignProcessToJobObject(job: HANDLE, proc: HANDLE) -> BOOL;
    pub(crate) fn ResumeThread(thread: HANDLE) -> u32;
    pub(crate) fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    pub(crate) fn TerminateJobObject(job: HANDLE, code: u32) -> BOOL;
    pub(crate) fn OpenProcess(access: u32, inherit: BOOL, pid: u32) -> HANDLE;
    pub(crate) fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> BOOL;
    pub(crate) fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attr: usize,
        value: *const c_void,
        size: usize,
        prev: *mut c_void,
        ret: *mut usize,
    ) -> BOOL;
    pub(crate) fn DeleteProcThreadAttributeList(list: *mut c_void);
    pub(crate) fn CreateMutexW(sa: *const c_void, owner: BOOL, name: *const u16) -> HANDLE;
    pub(crate) fn Sleep(ms: u32);
    pub(crate) fn LocalFree(p: *mut c_void) -> *mut c_void;
}

#[link(name = "kernelbase", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn IsApiSetImplemented(contract: *const u8) -> BOOL;
    pub(crate) fn CreateAppContainerProfile(
        name: *const u16,
        display: *const u16,
        desc: *const u16,
        caps: *const c_void,
        cap_count: u32,
        sid: *mut PSID,
    ) -> HRESULT;
    pub(crate) fn DeleteAppContainerProfile(name: *const u16) -> HRESULT;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn RegOpenKeyExW(
        key: HKEY,
        sub: *const u16,
        opts: u32,
        access: u32,
        out: *mut HKEY,
    ) -> u32;
    pub(crate) fn RegQueryValueExW(
        key: HKEY,
        name: *const u16,
        res: *mut u32,
        ty: *mut u32,
        data: *mut u8,
        len: *mut u32,
    ) -> u32;
    pub(crate) fn RegCloseKey(key: HKEY) -> u32;
    pub(crate) fn RegCreateKeyExW(
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
    pub(crate) fn RegDeleteKeyW(key: HKEY, sub: *const u16) -> u32;
    pub(crate) fn OpenProcessToken(proc: HANDLE, access: u32, out: *mut HANDLE) -> BOOL;
    pub(crate) fn GetTokenInformation(
        token: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> BOOL;
    pub(crate) fn ConvertSidToStringSidW(sid: PSID, out: *mut *mut u16) -> BOOL;
    pub(crate) fn ConvertStringSidToSidW(s: *const u16, sid: *mut PSID) -> BOOL;
    pub(crate) fn GetNamedSecurityInfoW(
        name: *const u16,
        obj_type: u32,
        info: u32,
        owner: *mut PSID,
        group: *mut PSID,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        sd: *mut *mut c_void,
    ) -> u32;
    pub(crate) fn SetNamedSecurityInfoW(
        name: *mut u16,
        obj_type: u32,
        info: u32,
        owner: PSID,
        group: PSID,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;
    pub(crate) fn SetEntriesInAclW(
        count: u32,
        ea: *const ExplicitAccessW,
        old: *const c_void,
        new_acl: *mut *mut c_void,
    ) -> u32;
    pub(crate) fn FreeSid(sid: PSID) -> PSID;
}

#[link(name = "version", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn GetFileVersionInfoSizeExW(
        flags: u32,
        name: *const u16,
        handle: *mut u32,
    ) -> u32;
    pub(crate) fn GetFileVersionInfoExW(
        flags: u32,
        name: *const u16,
        handle: u32,
        len: u32,
        data: *mut c_void,
    ) -> BOOL;
    pub(crate) fn VerQueryValueW(
        data: *const c_void,
        sub: *const u16,
        buf: *mut *mut c_void,
        len: *mut u32,
    ) -> BOOL;
}

#[link(name = "combase", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn RoInitialize(kind: u32) -> HRESULT;
    pub(crate) fn RoGetActivationFactory(
        name: *const c_void,
        iid: *const c_void,
        out: *mut *mut c_void,
    ) -> HRESULT;
    pub(crate) fn WindowsCreateString(
        src: *const u16,
        len: u32,
        out: *mut *mut c_void,
    ) -> HRESULT;
    pub(crate) fn WindowsDeleteString(s: *mut c_void) -> HRESULT;
    pub(crate) fn WindowsGetStringRawBuffer(s: *const c_void, len: *mut u32) -> *const u16;
}

#[link(name = "ole32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn CoUninitialize();
    pub(crate) fn CoTaskMemFree(p: *mut c_void);
}

// Raw Winsock2 — `std::net::TcpStream` *panics* when WSAStartup fails
// (LPAC denies the provider init), so the probe drives ws2_32 directly
// and records the real WSA codes instead of dying mid-JSON.
#[link(name = "ws2_32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn WSAStartup(req: u16, data: *mut u8) -> i32;
    pub(crate) fn WSACleanup() -> i32;
    pub(crate) fn socket(af: i32, ty: i32, proto: i32) -> usize;
    pub(crate) fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    pub(crate) fn closesocket(s: usize) -> i32;
    pub(crate) fn WSAGetLastError() -> i32;
}
