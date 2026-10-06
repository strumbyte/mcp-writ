//! Shared helpers: UTF-16/JSON plumbing, registry + file version reads,
//! token facts, and system-DLL loading used by the contract legs.

use std::ffi::c_void;
use std::path::PathBuf;

use crate::ffi::*;

pub(crate) fn wide(s: &str) -> Vec<u16> {
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

pub(crate) fn js(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

pub(crate) fn jopt(s: Option<String>) -> String {
    s.map(|v| js(&v)).unwrap_or_else(|| "null".into())
}

fn sys32_path(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(name)
}

pub(crate) fn hr_str(hr: i32) -> String {
    format!("0x{hr:08x}")
}

/// One JSON record per file probe: presence + version resource.
pub(crate) fn file_fact(name: &str) -> String {
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
pub(crate) fn reg_read(root: HKEY, sub: &str, value: &str) -> Option<String> {
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

pub(crate) fn reg_dword(root: HKEY, sub: &str, value: &str) -> Option<u32> {
    reg_read(root, sub, value).and_then(|s| s.parse().ok())
}

/// Service registration facts (registry presence only — never SCM control).
pub(crate) fn service_fact(name: &str) -> String {
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
pub(crate) fn token_facts() -> String {
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

/// Load a System32 DLL by bare name (search is pinned to System32).
pub(crate) fn load_system_dll(name: &str) -> HANDLE {
    unsafe {
        LoadLibraryExW(
            wide(name).as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
}

pub(crate) fn export_addr(dll: HANDLE, name: &str) -> *mut c_void {
    unsafe {
        let c = std::ffi::CString::new(name).unwrap();
        GetProcAddress(dll, c.as_ptr() as *const u8)
    }
}
