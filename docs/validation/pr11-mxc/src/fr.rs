// direct read probe: args = paths to fs::read
fn main() {
    for p in std::env::args().skip(1) {
        match std::fs::read(&p) {
            Ok(d) => println!("{p}: ok {}B", d.len()),
            Err(e) => println!("{p}: err:{}", e.raw_os_error().unwrap_or(-1)),
        }
    }
}
