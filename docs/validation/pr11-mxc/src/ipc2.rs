// remaining IPC/socket surface: AF_UNIX, mailslot, raw socket, UDP inbound
// args: <writable_dir>
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[link(name = "ws2_32")]
extern "system" {
    fn WSASocketW(af: i32, ty: i32, proto: i32, info: *mut u8, g: u32, flags: u32) -> usize;
    fn WSAGetLastError() -> i32;
    fn closesocket(s: usize) -> i32;
    fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
    fn WSAStartup(w: u16, data: *mut u8) -> i32;
    fn sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateMailslotW(lpName: *const u16, nMaxMessageSize: u32, lReadTimeout: u32, lpSecurityAttributes: *mut core::ffi::c_void) -> isize;
    fn CreateFileW(lpFileName: *const u16, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: *mut core::ffi::c_void, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: isize) -> isize;
    fn GetLastError() -> u32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let wdir = std::env::args().nth(1).unwrap();
    unsafe {
        let mut d = [0u8; 512];
        WSAStartup(0x0202, d.as_mut_ptr());
    }

    // AF_UNIX via winsock — sockaddr_un {u16 family=1; char path[108]}
    let upath = format!("{wdir}\\probe.sock");
    let _ = std::fs::remove_file(&upath);
    unsafe {
        let s = WSASocketW(1 /*AF_UNIX*/, 1 /*SOCK_STREAM*/, 0, core::ptr::null_mut(), 0, 0);
        let mut sun = [0u8; 110];
        sun[0] = 1;
        let pb = upath.as_bytes();
        let n = pb.len().min(107);
        sun[2..2 + n].copy_from_slice(&pb[..n]);
        let r = bind(s, sun.as_ptr(), (2 + n + 1) as i32);
        println!("af_unix bind -> r={} err={}", r, WSAGetLastError());
        if s != usize::MAX {
            closesocket(s);
        }
    }

    // mailslot — datagram IPC endpoint
    let m = unsafe { CreateMailslotW(w(r"\\.\mailslot\mxc_slot").as_ptr(), 0, 0, core::ptr::null_mut()) };
    println!("create mailslot -> h={} err={}", m, unsafe { GetLastError() });
    let hm = unsafe {
        CreateFileW(
            w(r"\\.\mailslot\hostslot").as_ptr(),
            0x40000000,
            0,
            core::ptr::null_mut(),
            3,
            0,
            0,
        )
    };
    println!("open host mailslot -> h={} err={}", hm, unsafe { GetLastError() });

    // raw sockets — potential egress bypass like UDP
    unsafe {
        for (proto, label) in [(6i32, "raw TCP"), (1, "raw ICMP")] {
            let s = WSASocketW(2, 3, proto, core::ptr::null_mut(), 0, 0);
            println!("{label} socket -> s={} err={}", s as i64, WSAGetLastError());
            if proto == 1 && s != usize::MAX {
                // ICMP echo request to external — does it actually leave the box?
                let mut pkt = [0u8; 12];
                pkt[0] = 8; // type echo
                pkt[4] = 0x12; pkt[5] = 0x34; // id
                // ICMP checksum (RFC 1071) over the packet, cksum zeroed
                let mut sum: u32 = 0;
                for i in (0..12).step_by(2) {
                    sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
                }
                sum = (sum >> 16) + (sum & 0xffff);
                sum += sum >> 16;
                let c = !(sum as u16);
                pkt[2] = (c >> 8) as u8;
                pkt[3] = c as u8;
                // sockaddr_in for 203.0.113.1: AF_INET (u16) + port(0) + addr
                let d = [2u8, 0, 0, 0, 203, 0, 113, 1, 0, 0, 0, 0, 0, 0, 0, 0];
                let r = sendto(s, pkt.as_ptr(), pkt.len() as i32, 0, d.as_ptr() as *const u8, 16);
                println!("raw ICMP sendto -> r={} err={}", r, WSAGetLastError());
            }
            if s != usize::MAX {
                closesocket(s);
            }
        }
    }

    // UDP inbound on wildcard — delivery from host LAN-ip source?
    match std::net::UdpSocket::bind("0.0.0.0:62445") {
        Ok(u) => {
            println!("udp bind *:62445 -> ok, waiting 4s");
            u.set_read_timeout(Some(std::time::Duration::from_secs(4))).ok();
            let mut b = [0u8; 64];
            match u.recv_from(&mut b) {
                Ok((n, a)) => println!("udp wildcard recv -> {}B from {a} (DELIVERED)", n),
                Err(e) => println!("udp wildcard recv -> err:{}", e.raw_os_error().unwrap_or(-1)),
            }
        }
        Err(e) => println!("udp wildcard bind -> err:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // UDP inbound — can the container RECEIVE datagrams (covert channel in)?
    match std::net::UdpSocket::bind("127.0.0.1:62444") {
        Ok(u) => {
            println!("udp bind 62444 -> ok, waiting 3s");
            u.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
            let mut b = [0u8; 64];
            match u.recv_from(&mut b) {
                Ok((n, a)) => println!("udp recv -> {}B from {a} (INBOUND DELIVERED)", n),
                Err(e) => println!("udp recv -> err:{} {}", e.raw_os_error().unwrap_or(-1), e),
            }
        }
        Err(e) => println!("udp bind -> err:{}", e.raw_os_error().unwrap_or(-1)),
    }
}
