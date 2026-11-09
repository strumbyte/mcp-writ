// socket family sweep + self-loopback
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[link(name = "ws2_32")]
extern "system" {
    fn WSASocketW(af: i32, ty: i32, proto: i32, info: *mut u8, g: u32, flags: u32) -> usize;
    fn WSAGetLastError() -> i32;
    fn closesocket(s: usize) -> i32;
    fn WSAStartup(w: u16, data: *mut u8) -> i32;
}

fn main() {
    unsafe {
        let mut d = [0u8; 512];
        WSAStartup(0x0202, d.as_mut_ptr());
    }
    // family sweep: AF_INET6=23 AF_BTH=32 AF_HYPERV=34 AF_NETBIOS=17 AF_IRDA=26 AF_VSOCK? (40/41)
    for (af, name) in [
        (23i32, "AF_INET6"),
        (32, "AF_BTH"),
        (34, "AF_HYPERV"),
        (17, "AF_NETBIOS"),
        (26, "AF_IRDA"),
        (40, "AF_VSOCK?"),
        (6, "AF_IPX"),
    ] {
        let s = unsafe { WSASocketW(af, 1, 0, core::ptr::null_mut(), 0, 0) };
        println!("{name} (af={af}) stream -> s={} err={}", s as i64, unsafe { WSAGetLastError() });
        if s != usize::MAX {
            unsafe { closesocket(s) };
        }
    }
    // v6 UDP egress — already proven open; check v6 TCP rule enforcement quickly
    // self-loopback: bind + connect to own listener on 127.0.0.1
    match TcpListener::bind("127.0.0.1:62599") {
        Ok(l) => {
            println!("self bind ok");
            let port = l.local_addr().unwrap().port();
            let h = std::thread::spawn(move || {
                l.set_nonblocking(true).ok();
                let t = std::time::Instant::now();
                while t.elapsed() < Duration::from_secs(10) {
                    match l.accept() {
                        Ok(_) => break,
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            });
            match TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_secs(3),
            ) {
                Ok(_) => println!("self loopback connect -> CONNECTED"),
                Err(e) => println!("self loopback connect -> err {}", e.raw_os_error().unwrap_or(-1)),
            }
            let _ = h.join();
        }
        Err(e) => println!("self bind -> err {}", e.raw_os_error().unwrap_or(-1)),
    }
}
