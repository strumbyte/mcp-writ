use std::net::TcpListener; use std::io::Read;
#[link(name="kernel32")] extern "system" { fn GetCurrentProcess()->isize; fn CloseHandle(h:isize)->i32; }
#[link(name="advapi32")] extern "system" {
    fn OpenProcessToken(p:isize,a:u32,h:*mut isize)->i32;
    fn GetTokenInformation(h:isize,c:u32,i:*mut u8,l:u32,r:*mut u32)->i32;
    fn ConvertSidToStringSidA(s:*const u8,o:*mut *mut u8)->i32;
    fn LocalFree(h:isize)->isize;
}
fn main(){ unsafe{
    let mut th=0isize; let mut sidstr=String::from("nosid");
    if OpenProcessToken(GetCurrentProcess(),8,&mut th)!=0 {
        let mut buf=[0usize;32]; let mut rl=0u32;
        if GetTokenInformation(th,31,buf.as_mut_ptr() as *mut u8,256,&mut rl)!=0 {
            let psid=buf[0];
            let mut o:*mut u8=std::ptr::null_mut();
            if ConvertSidToStringSidA(psid as *const u8,&mut o)!=0 {
                sidstr=std::ffi::CStr::from_ptr(o as *const i8).to_str().unwrap_or("?").to_string(); LocalFree(o as isize); }
        }
        CloseHandle(th);
    }
    let port:u16=std::env::args().nth(1).unwrap().parse().unwrap();
    let sidfile=std::env::args().nth(2).unwrap();
    println!("AC_SID={sidstr}"); std::fs::write(&sidfile,format!("{sidstr}")).ok();
    if let Ok(l)=TcpListener::bind(("0.0.0.0",port)){ println!("LISTENING"); l.set_nonblocking(true).ok();
        let t=std::time::Instant::now();
        while t.elapsed()<std::time::Duration::from_secs(40){
            match l.accept(){ Ok((mut s,a))=>{ let mut b=[0u8;64]; let n=s.read(&mut b).unwrap_or(0); println!("ACCEPTED from {a} {n}B"); break } Err(_)=>std::thread::sleep(std::time::Duration::from_millis(150)) }
        }
    } else { println!("bind fail") }
}}
