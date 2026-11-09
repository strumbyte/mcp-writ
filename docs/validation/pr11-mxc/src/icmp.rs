use std::os::windows::ffi::OsStrExt; use std::ffi::OsStr;
#[link(name="iphlpapi")] extern "system" {
    fn IcmpCreateFile()->isize;
    fn IcmpSendEcho(h:isize,d:u32,r:*const u8,s:u16,o:*const u8,rep:*mut u8,rs:u32,t:u32)->u32;
    fn IcmpCloseHandle(h:isize)->i32;
}
fn main(){ unsafe{
    let h=IcmpCreateFile(); println!("icmp_handle={h}");
    if h!=0 { let data=[0u8;32]; let mut rep=vec![0u8;64+270]; 
        let r=IcmpSendEcho(h,0x08080808u32.to_be().swap_bytes(),data.as_ptr(),32,std::ptr::null(),rep.as_mut_ptr(),64+270,2000);
        println!("echo 8.8.8.8 -> replies={}",r);
        let r2=IcmpSendEcho(h,u32::from_ne_bytes([127,0,0,1]),data.as_ptr(),32,std::ptr::null(),rep.as_mut_ptr(),64+270,1000);
        println!("echo 127.0.0.1 -> replies={}",r2);
        IcmpCloseHandle(h); }
}}
