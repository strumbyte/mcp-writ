use std::net::ToSocketAddrs;

fn main() {
    for name in ["example.com:80", "localhost:80", "nonexistent.invalid:80"] {
        match name.to_socket_addrs() {
            Ok(mut it) => {
                let v: Vec<_> = it.by_ref().collect();
                println!("{name} -> ok {v:?}");
            }
            Err(e) => println!("{name} -> err {e}"),
        }
    }
}
