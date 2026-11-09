use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

type HW = isize;
#[link(name = "user32")]
extern "system" {
    fn GetThreadDesktop(tid: u32) -> HW;
    fn GetCurrentThreadId() -> u32;
    fn GetUserObjectInformationW(h: HW, idx: i32, buf: *mut u16, len: u32, out: *mut u32) -> i32;
    fn OpenInputDesktop(flags: u32, inherit: i32, access: u32) -> HW;
    fn OpenWindowStationW(name: *const u16, inherit: i32, access: u32) -> HW;
    fn OpenDesktopW(name: *const u16, flags: u32, inherit: i32, access: u32) -> HW;
    fn EnumWindows(cb: extern "system" fn(HW, isize) -> i32, p: isize) -> i32;
    fn GetForegroundWindow() -> HW;
    fn GetWindowTextW(h: HW, buf: *mut u16, len: i32) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

unsafe fn name_of(h: HW) -> String {
    let mut buf = [0u16; 256];
    let mut out = 0u32;
    if GetUserObjectInformationW(h, 2, buf.as_mut_ptr(), 512, &mut out) != 0 {
        // `out` is a byte count — halve for UTF-16 elements, drop the
        // terminating NUL so the name carries no NULs.
        let chars = ((out as usize) / 2).min(256);
        String::from_utf16_lossy(&buf[..chars.saturating_sub(1)])
    } else {
        format!("<err {}>", GetLastError())
    }
}

static mut COUNT: usize = 0;
static mut FOREGROUND_SEEN: bool = false;
static mut FG_HW: HW = 0;

extern "system" fn cb(h: HW, _p: isize) -> i32 {
    unsafe {
        COUNT += 1;
        if h == FG_HW {
            FOREGROUND_SEEN = true;
        }
    }
    1
}

fn main() {
    unsafe {
        let td = GetThreadDesktop(GetCurrentThreadId());
        println!("thread_desktop={} name={}", td, name_of(td));

        let ws = OpenWindowStationW(w("WinSta0").as_ptr(), 0, 0x0001);
        let e1 = GetLastError();
        if ws != 0 {
            println!("open_winsta0=ok name={}", name_of(ws));
        } else {
            println!("open_winsta0=FAIL err={e1}");
        }

        let dt = OpenDesktopW(w("Default").as_ptr(), 0, 0, 0x0001);
        let e2 = GetLastError();
        if dt != 0 {
            println!("open_desktop_default=ok name={}", name_of(dt));
        } else {
            println!("open_desktop_default=FAIL err={e2}");
        }

        let idt = OpenInputDesktop(0, 0, 0x0001);
        let e3 = GetLastError();
        if idt != 0 {
            println!("open_input_desktop=ok name={} (SAME-SESSION INPUT DESKTOP REACHABLE)", name_of(idt));
        } else {
            println!("open_input_desktop=FAIL err={e3}");
        }

        let fg = GetForegroundWindow();
        FG_HW = fg;
        let mut t = [0u16; 128];
        let n = GetWindowTextW(fg, t.as_mut_ptr(), 128);
        let title = String::from_utf16_lossy(&t[..n.max(0) as usize]);
        println!("foreground_window={:#x} title={:?}", fg, title);

        COUNT = 0;
        let r = EnumWindows(cb, 0);
        let e4 = GetLastError();
        println!("enum_windows ok={} count={} err={} foreground_in_view={}", r, COUNT, e4, FOREGROUND_SEEN);
    }
}
