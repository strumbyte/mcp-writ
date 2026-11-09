use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn main() {
    let port: u16 = std::env::args().nth(1).unwrap().parse().unwrap();
    let s = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut buf = [0u8; 512];
    let t0 = Instant::now();
    match s.recv_from(&mut buf) {
        Ok((n, from)) => println!("RX {n}B from {from} after {:?}", t0.elapsed()),
        Err(e) => println!("RX timeout/err {e}"),
    }
}
