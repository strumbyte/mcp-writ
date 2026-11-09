use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "userenv")]
extern "system" {
    fn CreateAppContainerProfile(
        n: *const u16,
        d: *const u16,
        desc: *const u16,
        c: *const u8,
        cc: u32,
        sid: *mut isize,
    ) -> i32;
    fn DeriveAppContainerSidFromAppContainerName(n: *const u16, sid: *mut isize) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn ConvertSidToStringSidA(s: *const u8, o: *mut *mut u8) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h: isize) -> isize;
    fn InitializeProcThreadAttributeList(l: *mut u8, c: u32, r: u32, s: *mut usize) -> i32;
    fn UpdateProcThreadAttribute(
        l: *mut u8,
        f: u32,
        a: usize,
        v: *const u8,
        sz: usize,
        p: *const u8,
        r: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(l: *mut u8);
    fn CreateProcessW(
        app: *const u16,
        cmd: *mut u16,
        pa: *const u8,
        ta: *const u8,
        inh: i32,
        f: u32,
        e: *const u8,
        d: *const u16,
        si: *mut u8,
        pi: *mut u8,
    ) -> i32;
    fn GetLastError() -> u32;
    fn CloseHandle(h: isize) -> i32;
    fn HeapAlloc(h: isize, f: u32, s: usize) -> *mut u8;
    fn GetProcessHeap() -> isize;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    unsafe {
        let name = "mxc.probe.proxy";
        let mut sid: isize = 0;
        let r = CreateAppContainerProfile(
            w(name).as_ptr(),
            w("MXC Probe Proxy").as_ptr(),
            w("peer test").as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        );
        println!("create_profile rc={r} err={}", GetLastError());
        if r == 0 || r == -2147024713 {
            sid = 0;
            DeriveAppContainerSidFromAppContainerName(w(name).as_ptr(), &mut sid);
        }
        println!("sid=0x{:x}", sid);
        let mut os: *mut u8 = std::ptr::null_mut();
        ConvertSidToStringSidA(sid as *const u8, &mut os);
        println!(
            "peer_sid={}",
            std::ffi::CStr::from_ptr(os as *const i8).to_str().unwrap()
        );
        LocalFree(os as isize);
        let mut sc = [0u8; 24];
        *(sc.as_mut_ptr() as *mut isize) = sid;
        let mut sz: usize = 0;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut sz);
        let al = HeapAlloc(GetProcessHeap(), 0, sz);
        InitializeProcThreadAttributeList(al, 1, 0, &mut sz);
        let ur = UpdateProcThreadAttribute(
            al as *mut u8,
            0,
            0x20009,
            sc.as_ptr(),
            24,
            std::ptr::null(),
            std::ptr::null_mut(),
        );
        println!("update_attr rc={ur} err={}", GetLastError());
        let mut si = [0u8; 112];
        *(si.as_mut_ptr() as *mut u32) = 112;
        *(si.as_mut_ptr().add(104) as *mut usize) = al as usize;
        let mut pi = [0u8; 24];
        let mut cmd = w(&std::env::args().nth(1).unwrap());
        let cr = CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0x00080000,
            std::ptr::null(),
            std::ptr::null(),
            si.as_mut_ptr(),
            pi.as_mut_ptr(),
        );
        println!("create_process rc={cr} err={}", GetLastError());
        if cr != 0 {
            let t = *(pi.as_ptr().add(8) as *const isize);
            println!("child_pid={}", *(pi.as_ptr().add(16) as *const u32));
            CloseHandle(t);
        }
        DeleteProcThreadAttributeList(al);
    }
}
