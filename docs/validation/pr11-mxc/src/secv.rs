// PSEC capability probe — the host's declared spec-feature flags
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(n: *const u16) -> isize;
    fn GetProcAddress(h: isize, n: *const u8) -> usize;
    fn GetLastError() -> u32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    unsafe {
        let h = LoadLibraryW(w("processmodel.dll").as_ptr());
        println!("processmodel.dll h={h:#x} err={}", GetLastError());
        if h == 0 {
            return;
        }
        type Q = unsafe extern "system" fn(*mut u64) -> i32;
        type V = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> i32;
        let q: Option<Q> = std::mem::transmute(GetProcAddress(
            h,
            b"QueryProcessSecurityEnvironmentSupport\0".as_ptr(),
        ));
        let v: Option<V> = std::mem::transmute(GetProcAddress(
            h,
            b"IsProcessSecurityEnvironmentVersionSupported\0".as_ptr(),
        ));
        if let Some(qf) = q {
            let mut flags: u64 = 0;
            let hr = qf(&mut flags);
            println!("QuerySupport -> hr={hr:#010x} flags={flags:#018x}");
            println!("  FileSystemDeny(0x1)     = {}", flags & 0x1 != 0);
            println!("  bit1 (0x2)              = {}", flags & 0x2 != 0);
            println!("  FileSystemEnumerate(0x4)= {}", flags & 0x4 != 0);
            println!("  NetworkIngress(0x8)     = {}", flags & 0x8 != 0);
            println!("  upper bits              = {:#x}", flags & !0xf);
        }
        if let Some(vf) = v {
            for major in 1u32..=2 {
                let mut avail: u8 = 0;
                let mut minor: u32 = 0;
                let hr = vf(major, &mut avail, &mut minor);
                println!("Version major={major} -> hr={hr:#010x} available={avail} minor={minor}");
            }
        }
    }
}
