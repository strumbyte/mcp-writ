use std::net::TcpListener; use std::io::Read;
fn main(){
    let port:u16=std::env::args().nth(1).unwrap().parse().unwrap();
    // UDP bind first — an idle host must not keep this check from running.
    match std::net::UdpSocket::bind(("0.0.0.0",port+1)){ Ok(_)=>println!("UDP_BIND_OK"), Err(e)=>println!("udp bind -> err {}",e.raw_os_error().unwrap_or(-1)) }
    match TcpListener::bind(("0.0.0.0",port)){
        Ok(l)=>{ println!("LISTEN_OK on 0.0.0.0:{port}"); l.set_nonblocking(true).ok();
            let t=std::time::Instant::now();
            while t.elapsed()<std::time::Duration::from_secs(40){
                match l.accept(){ Ok((mut s,a))=>{ let mut b=[0u8;64]; let n=s.read(&mut b).unwrap_or(0); println!("ACCEPTED from {a} {n}B"); break } Err(_)=>std::thread::sleep(std::time::Duration::from_millis(150)) }
            }
        }
        Err(e)=>println!("bind -> err {}", e.raw_os_error().unwrap_or(-1)),
    }
}
