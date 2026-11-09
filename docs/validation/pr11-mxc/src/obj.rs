use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn CreateMutexW(sec: isize, own: i32, name: *const u16) -> isize;
    fn OpenMutexW(acc: u32, own: i32, name: *const u16) -> isize;
    fn CreateEventW(sec: isize, man: i32, init: i32, name: *const u16) -> isize;
    fn OpenEventW(acc: u32, own: i32, name: *const u16) -> isize;
    fn CreateFileMappingW(f: isize, sec: isize, prot: u32, hi: u32, lo: u32, name: *const u16) -> isize;
    fn OpenFileMappingW(acc: u32, own: i32, name: *const u16) -> isize;
    fn GetLastError() -> u32;
    fn CloseHandle(h: isize) -> i32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "Pr11Shared".into());
    // 1) try to OPEN a host-created object (shared namespace?)
    for (label, open) in [
        ("mutex", w(&format!("Local\\{name}"))),
        ("event", w(&format!("Local\\{name}Ev"))),
        ("map", w(&format!("Local\\{name}Map"))),
        ("global_mutex", w(&format!("Global\\{name}"))),
    ] {
        let h = unsafe {
            match label {
                "mutex" | "global_mutex" => OpenMutexW(0x001F0001, 0, open.as_ptr()),
                "event" => OpenEventW(0x001F0003, 0, open.as_ptr()),
                _ => OpenFileMappingW(0x0004, 0, open.as_ptr()),
            }
        };
        let e = unsafe { GetLastError() };
        if h != 0 {
            println!("open_{label}=ok handle={h} (SHARED NAMESPACE — cross-boundary IPC)");
            unsafe { CloseHandle(h) };
        } else {
            println!("open_{label}=FAIL err={e}");
        }
    }
    // 2) create our own and report where it lands
    let mine = unsafe { CreateMutexW(0, 0, w(&format!("Local\\{name}FromChild")).as_ptr()) };
    let e = unsafe { GetLastError() };
    println!("create_own_mutex={} err={e}", if mine != 0 { "ok" } else { "FAIL" });
}
