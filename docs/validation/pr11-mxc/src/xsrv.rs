// cross-container server: creates named objects + binds loopback + records identity
// args: <shared_file>
use std::ffi::OsStr;
use std::io::Write;
use std::net::TcpListener;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn CreateMutexW(lpMutexAttributes: *mut core::ffi::c_void, bInitialOwner: i32, lpName: *const u16)
        -> isize;
    fn CreateNamedPipeW(
        lpName: *const u16, dwOpenMode: u32, dwPipeMode: u32, nMaxInstances: u32,
        nOutBufferSize: u32, nInBufferSize: u32, nDefaultTimeOut: u32,
        lpSecurityAttributes: *mut core::ffi::c_void,
    ) -> isize;
    fn GetCurrentProcessId() -> u32;
    fn GetLastError() -> u32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let shared = std::env::args().nth(1).unwrap();
    let pid = unsafe { GetCurrentProcessId() };
    let lap = std::env::var("LOCALAPPDATA").unwrap_or_default();
    // write a marker inside own package-local dir
    let own_file = format!("{lap}\\xsrv-marker.txt");
    let _ = std::fs::write(&own_file, b"container-a-secret");
    let m = unsafe { CreateMutexW(core::ptr::null_mut(), 0, w(r"Local\MXCXT_MUTEX").as_ptr()) };
    let p = unsafe {
        CreateNamedPipeW(
            w(r"\\.\pipe\mxcxt_pipe").as_ptr(),
            0x00000003, // PIPE_ACCESS_DUPLEX
            0,
            1,
            256,
            256,
            0,
            core::ptr::null_mut(),
        )
    };
    let lis = TcpListener::bind("127.0.0.1:62389");
    let liport = match &lis {
        Ok(l) => format!("ok {}", l.local_addr().unwrap()),
        Err(e) => format!("err:{}", e.raw_os_error().unwrap_or(-1)),
    };
    let mut f = std::fs::File::create(&shared).unwrap();
    writeln!(f, "pid={pid}").unwrap();
    writeln!(f, "lap={lap}").unwrap();
    writeln!(f, "own_file={own_file}").unwrap();
    writeln!(f, "mutex={m} err={}", unsafe { GetLastError() }).unwrap();
    writeln!(f, "pipe={p} err={}", unsafe { GetLastError() }).unwrap();
    writeln!(f, "listen={liport}").unwrap();
    drop(f);
    println!("XSRV_READY pid={pid} mutex={m} pipe={p} {liport}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    // keep objects alive; accept any inbound TCP to prove delivery
    if let Ok(l) = lis {
        l.set_nonblocking(true).ok();
        while std::time::Instant::now() < deadline {
            if let Ok((s, _)) = l.accept() {
                drop(s);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    } else {
        std::thread::sleep(std::time::Duration::from_secs(40));
    }
}
