use std::net::UdpSocket;
fn main(){
    for a in ["[::1]:53","[fd00::1]:53","127.0.0.1:53"]{
        // Bind the wildcard matching the target's family so the send
        // result reflects policy, not an address-family mismatch.
        let s=if a.starts_with('['){ UdpSocket::bind(("::",0)) } else { UdpSocket::bind(("0.0.0.0",0)) };
        match s{ Ok(so)=>{ let r=so.send_to(b"X",a); println!("{a} sendto -> {}",r.map(|n|format!("ok {n}B")).unwrap_or_else(|e|format!("err {}",e.raw_os_error().unwrap_or(-1)))) } Err(e)=>println!("bind err {e}") }
    }
}
