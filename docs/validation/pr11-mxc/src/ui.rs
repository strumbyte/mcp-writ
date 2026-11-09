use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[allow(non_snake_case)]
type HWND = isize;
type UINT = u32;
type WPARAM = usize;
type LPARAM = isize;
type BOOL = i32;

#[link(name = "user32")]
extern "system" {
    fn OpenClipboard(h: HWND) -> BOOL;
    fn CloseClipboard() -> BOOL;
    fn GetClipboardData(f: UINT) -> isize;
    fn SetClipboardData(f: UINT, h: isize) -> isize;
    fn SendInput(n: UINT, p: *const u8, sz: i32) -> UINT;
    fn CreateWindowExW(
        ex: u32, cls: *const u16, name: *const u16, style: u32,
        x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: isize, inst: isize, param: isize,
    ) -> HWND;
    fn SystemParametersInfoW(action: UINT, p1: UINT, p2: LPARAM, winini: UINT) -> BOOL;
    fn GetSystemMetrics(idx: i32) -> i32;
    fn RegisterClassW(cls: *const WNDCLASSW) -> u16;
    fn DestroyWindow(h: HWND) -> BOOL;
    fn DefWindowProcW(h: HWND, m: UINT, w: WPARAM, l: LPARAM) -> LPARAM;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

#[repr(C)]
struct WNDCLASSW {
    style: u32,
    wndproc: isize,
    cbcls: i32,
    cbwnd: i32,
    hinst: isize,
    hicon: isize,
    hcursor: isize,
    hbrush: isize,
    menu: *const u16,
    cls: *const u16,
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn main() {
    // clipboard read attempt
    let opened = unsafe { OpenClipboard(0) };
    let e1 = unsafe { GetLastError() };
    if opened != 0 {
        let data = unsafe { GetClipboardData(1) };
        let e2 = unsafe { GetLastError() };
        unsafe { CloseClipboard() };
        println!("clipboard_read: open=ok get={data} err={e2}");
    } else {
        println!("clipboard_read: open=FAIL err={e1}");
    }

    // clipboard write attempt (needs open first)
    let opened = unsafe { OpenClipboard(0) };
    if opened != 0 {
        let r = unsafe { SetClipboardData(1, 0) };
        let e = unsafe { GetLastError() };
        unsafe { CloseClipboard() };
        println!("clipboard_write: open=ok set={r} err={e}");
    } else {
        println!("clipboard_write: open=FAIL");
    }

    // input injection: a real keyboard event — INPUT_KEYBOARD(1),
    // KEYBDINPUT{wVk=0x41('A'),wScan=0,flags=0,time=0,extra=0}
    // INPUT layout x64: type u32 + pad4 + union(32) = 40 bytes;
    // ki: wVk@8, wScan@10, dwFlags@12, time@16, dwExtraInfo@24
    let mut input = [0u8; 80];
    input[0..4].copy_from_slice(&1u32.to_le_bytes()); // type = INPUT_KEYBOARD
    input[8..10].copy_from_slice(&0x41u16.to_le_bytes()); // ki.wVk = 'A' (down)
    input[40..44].copy_from_slice(&1u32.to_le_bytes()); // type = INPUT_KEYBOARD
    input[48..50].copy_from_slice(&0x41u16.to_le_bytes()); // ki.wVk = 'A'
    input[52..56].copy_from_slice(&0x0002u32.to_le_bytes()); // ki.dwFlags = KEYEVENTF_KEYUP
    let sent = unsafe { SendInput(2, input.as_ptr(), 40) };
    let e = unsafe { GetLastError() };
    println!("send_input_keyA: sent={sent} err={e}");

    // window creation (win32k surface)
    let cls_name = w("MCUI");
    let wc = WNDCLASSW {
        style: 0,
        wndproc: DefWindowProcW as isize,
        cbcls: 0,
        cbwnd: 0,
        hinst: 0,
        hicon: 0,
        hcursor: 0,
        hbrush: 0,
        menu: std::ptr::null(),
        cls: cls_name.as_ptr(),
    };
    let atom = unsafe { RegisterClassW(&wc) };
    let e = unsafe { GetLastError() };
    if atom == 0 {
        println!("window: register_class=FAIL err={e}");
        let metrics = unsafe { GetSystemMetrics(0) };
        println!("get_system_metrics: cx={metrics}");
    } else {
        let hwnd = unsafe {
            CreateWindowExW(
                0, cls_name.as_ptr(), cls_name.as_ptr(), 0,
                0, 0, 10, 10, 0, 0, 0, 0,
            )
        };
        let e = unsafe { GetLastError() };
        if hwnd != 0 {
            unsafe { DestroyWindow(hwnd) };
            println!("window: create=ok destroyed");
        } else {
            println!("window: create=FAIL err={e}");
        }
    }

    // system parameters (SPI_SETBEEP=0x0002 write attempt)
    let r = unsafe { SystemParametersInfoW(0x0002, 1, 0, 0) };
    let e = unsafe { GetLastError() };
    println!("system_params_write: ok={r} err={e}");
}
