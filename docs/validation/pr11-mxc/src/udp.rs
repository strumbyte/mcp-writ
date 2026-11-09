use std::net::{ToSocketAddrs, UdpSocket};

fn main() {
    for arg in std::env::args().skip(1) {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                println!("{arg} bind -> err {e}");
                continue;
            }
        };
        let addrs: Vec<_> = match arg.to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(e) => {
                println!("{arg} parse -> err {e}");
                continue;
            }
        };
        let sa = match addrs.first() {
            Some(s) => *s,
            None => continue,
        };
        match sock.send_to(b"x", sa) {
            Ok(n) => println!("{arg} sendto -> ok {n}B"),
            Err(e) => println!("{arg} sendto -> err {e}"),
        }
        match sock.connect(sa) {
            Ok(()) => match sock.send(b"y") {
                Ok(n) => println!("{arg} connect+send -> ok {n}B"),
                Err(e) => println!("{arg} connect+send -> err {e}"),
            },
            Err(e) => println!("{arg} connect -> err {e}"),
        }
    }
}
