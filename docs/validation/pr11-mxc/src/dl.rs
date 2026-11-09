use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(n: *const u16) -> isize;
    fn GetLastError() -> u32;
}
fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}
fn main() {
    for d in ["user32.dll", "ole32.dll", "gdi32.dll"] {
        let h = unsafe { LoadLibraryW(w(d).as_ptr()) };
        let e = unsafe { GetLastError() };
        println!("{d}: h={h:#x} err={e}");
    }
}
