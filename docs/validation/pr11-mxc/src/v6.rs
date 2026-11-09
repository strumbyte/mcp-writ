use std::net::{TcpStream, ToSocketAddrs};

fn main() {
    for arg in std::env::args().skip(1) {
        let (tx, rx) = std::sync::mpsc::channel();
        let a = arg.clone();
        std::thread::spawn(move || {
            let r = match a.to_socket_addrs() {
                Ok(mut it) => match it.next() {
                    Some(sa) => match TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(3)) {
                        Ok(_) => "ok connected".to_string(),
                        Err(e) => format!("err {e}"),
                    },
                    None => "err no-addrs".to_string(),
                },
                Err(e) => format!("parse-err {e}"),
            };
            let _ = tx.send(r);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(4)) {
            Ok(m) => println!("{arg} -> {m}"),
            Err(_) => println!("{arg} -> timeout"),
        }
    }
}
