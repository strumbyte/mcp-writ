// token surface: integrity level, elevation, groups count
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(p: isize, a: u32, t: *mut isize) -> i32;
    fn GetTokenInformation(t: isize, c: u32, i: *mut u8, l: u32, r: *mut u32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> isize;
    fn GetLastError() -> u32;
    fn CloseHandle(h: isize) -> i32;
    fn lstrlenW(p: *const u16) -> i32;
}

fn main() {
    unsafe {
        let mut t: isize = 0;
        let ok = OpenProcessToken(GetCurrentProcess(), 0x0008 /*QUERY*/, &mut t);
        println!("OpenProcessToken -> ok={} err={}", ok, GetLastError());
        // TokenIntegrityLevel = 25
        let mut need = 0u32;
        GetTokenInformation(t, 25, core::ptr::null_mut(), 0, &mut need);
        let mut buf = vec![0usize; (need as usize).div_ceil(8)];
        let ok2 = GetTokenInformation(t, 25, buf.as_mut_ptr() as *mut u8, need, &mut need);
        if ok2 != 0 {
            // TOKEN_MANDATORY_LABEL: SID_AND_ATTRIBUTES { PSID sid; u32 attrs }
            let psid = buf[0];
            // SID: rev(1) subcount(1) idauth(6) then u32 subauth[]
            let sc = *((psid + 1) as *const u8);
            let il = *((psid + 8 + 4 * (sc as usize - 1)) as *const u32);
            let label = match il {
                0x0000 => "Untrusted",
                0x1000 => "Low",
                0x2000 => "Medium",
                0x3000 => "High",
                0x4000 => "System",
                _ => "?",
            };
            println!("IntegrityLevel -> {label} (0x{il:x})");
        } else {
            println!("IntegrityLevel -> err {}", GetLastError());
        }
        // TokenElevationType = 18, TokenAppContainerSid presence = 31 already probed
        let mut need2 = 0u32;
        let mut v = [0u8; 4];
        if GetTokenInformation(t, 18, v.as_mut_ptr(), 4, &mut need2) != 0 {
            let et = u32::from_le_bytes(v);
            println!("ElevationType -> {et} (1=Default,2=Full,3=Limited)");
        }
        // TokenIsAppContainer = 29
        if GetTokenInformation(t, 29, v.as_mut_ptr(), 4, &mut need2) != 0 {
            println!("IsAppContainer -> {}", u32::from_le_bytes(v));
        }
        CloseHandle(t);
    }
}
