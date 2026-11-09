use std::os::windows::ffi::OsStrExt; use std::ffi::OsStr;
#[link(name="kernel32")] extern "system" {
    fn CreateNamedPipeW(n:*const u16,o:u32,p:u32,m:u32,i:u32,o2:u32,d:u32,s:*const u8)->isize;
    fn CreateFileW(n:*const u16,a:u32,s:u32,x:*const u8,d:u32,f:u32,t:isize)->isize;
    fn GetLastError()->u32; fn CloseHandle(h:isize)->i32; fn WaitNamedPipeW(n:*const u16,t:u32)->i32;
}
fn w(s:&str)->Vec<u16>{OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()}
fn main(){ unsafe{
    // try to open a host-created pipe (arg0 = pipe name)
    let p=std::env::args().nth(1).unwrap_or("\\\\.\\pipe\\mxc_probe_pipe".into());
    let h=CreateFileW(w(&p).as_ptr(),0xC0000000,0,std::ptr::null(),3,0,0);
    println!("open_host_pipe -> {}", if h!=0usize as isize && h!=-1isize {"ok".into()} else {format!("err {}",GetLastError())});
    if h!=0usize as isize && h!=-1isize {CloseHandle(h);}
    // create own pipe (server side)
    let own=CreateNamedPipeW(w("\\\\.\\pipe\\mxc_own_pipe").as_ptr(),3,0,1,512,512,0,std::ptr::null());
    println!("create_own_pipe -> {}", if own!=0usize as isize && own!=-1isize {"ok".into()} else {format!("err {}",GetLastError())});
    if own!=0usize as isize && own!=-1isize {CloseHandle(own);}
    // system pipe
    let h2=CreateFileW(w("\\\\.\\pipe\\lsarpc").as_ptr(),0xC0000000,0,std::ptr::null(),3,0x80,0);
    println!("open_lsarpc -> {}", if h2!=0usize as isize && h2!=-1isize {"ok".into()} else {format!("err {}",GetLastError())});
    if h2!=0usize as isize && h2!=-1isize {CloseHandle(h2);}
}}
