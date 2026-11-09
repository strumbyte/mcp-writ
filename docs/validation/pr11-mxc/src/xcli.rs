// cross-container client: probes sibling container's objects/pipe/socket/pid/files
// args: <shared_file>
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn OpenMutexW(dwDesiredAccess: u32, bInheritHandle: i32, lpName: *const u16) -> isize;
    fn CreateFileW(
        lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32,
        lpSecurityAttributes: *mut core::ffi::c_void, dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32, hTemplateFile: isize,
    ) -> isize;
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
    fn CloseHandle(h: isize) -> i32;
    fn GetLastError() -> u32;
}

#[link(name = "psapi")]
extern "system" {
    fn EnumProcesses(lpidProcess: *mut u32, cb: u32, lpcbNeeded: *mut u32) -> i32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let shared = std::env::args().nth(1).unwrap();
    let info = std::fs::read_to_string(&shared).unwrap_or_default();
    println!("sibling-info: {}", info.replace('\n', " | "));
    let pid: u32 = info
        .lines()
        .find(|l| l.starts_with("pid="))
        .and_then(|l| l[4..].parse().ok())
        .unwrap_or(0);
    let own_file = info
        .lines()
        .find(|l| l.starts_with("own_file="))
        .map(|l| l[9..].to_string())
        .unwrap_or_default();

    // named mutex of sibling
    let h = unsafe { OpenMutexW(0x00100000, 0, w(r"Local\MXCXT_MUTEX").as_ptr()) };
    println!("open sibling mutex -> h={} err={}", h, unsafe { GetLastError() });
    if h != 0 {
        unsafe { CloseHandle(h) };
    }

    // named pipe of sibling
    let hp = unsafe {
        CreateFileW(
            w(r"\\.\pipe\mxcxt_pipe").as_ptr(),
            0xC0000000, // GENERIC_READ|WRITE
            0,
            core::ptr::null_mut(),
            3, // OPEN_EXISTING
            0,
            0,
        )
    };
    println!("open sibling pipe -> h={} err={}", hp, unsafe { GetLastError() });
    if hp > 0 {
        unsafe { CloseHandle(hp) };
    }

    // loopback TCP to sibling's listener + a host-side listener (control)
    for addr in ["127.0.0.1:62389", "127.0.0.1:62390"] {
        match std::net::TcpStream::connect(addr) {
            Ok(_) => println!("tcp {addr} -> ok CONNECTED (cross-container channel)"),
            Err(e) => println!("tcp {addr} -> err:{}", e.raw_os_error().unwrap_or(-1)),
        }
    }

    // sibling's package-local file
    if !own_file.is_empty() {
        match std::fs::read(&own_file) {
            Ok(d) => println!("sibling package file -> ok {}B (LEAK)", d.len()),
            Err(e) => println!("sibling package file -> err:{}", e.raw_os_error().unwrap_or(-1)),
        }
    }

    // sibling pid open + process enumeration
    if pid != 0 {
        let hp2 = unsafe { OpenProcess(0x0400, 0, pid) }; // PROCESS_QUERY_INFORMATION
        println!("open sibling pid -> h={} err={}", hp2, unsafe { GetLastError() });
        if hp2 != 0 {
            unsafe { CloseHandle(hp2) };
        }
    }
    unsafe {
        let mut buf = [0u32; 1024];
        let mut need = 0u32;
        EnumProcesses(buf.as_mut_ptr(), 4096, &mut need);
        let n = need as usize / 4;
        let list = &buf[..n.min(64)];
        println!("EnumProcesses -> {} pids: {:?}", n, list);
    }

    // own identity
    println!(
        "own LOCALAPPDATA={}",
        std::env::var("LOCALAPPDATA").unwrap_or_default()
    );
}
