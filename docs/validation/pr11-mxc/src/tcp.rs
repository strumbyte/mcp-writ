// tcp connect probe: args = addr1 [addr2 ...]
use std::net::TcpStream;
use std::time::Duration;
fn main() {
    for a in std::env::args().skip(1) {
        match a.parse::<std::net::SocketAddr>() {
            Ok(sa) => match TcpStream::connect_timeout(&sa, Duration::from_secs(4)) {
                Ok(_) => println!("{a} -> CONNECTED"),
                Err(e) => println!("{a} -> err {}", e.raw_os_error().unwrap_or(-1)),
            },
            Err(_) => println!("{a} -> bad addr"),
        }
    }
}
