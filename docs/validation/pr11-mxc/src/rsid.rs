use std::os::windows::ffi::OsStrExt;
#[link(name="kernel32")] extern "system" { fn OpenProcess(a:u32,b:i32,c:u32)->isize; fn CloseHandle(h:isize)->i32; }
#[link(name="advapi32")] extern "system" {
    fn OpenProcessToken(p:isize,a:u32,h:*mut isize)->i32;
    fn GetTokenInformation(h:isize,c:u32,i:*mut u8,l:u32,r:*mut u32)->i32;
    fn ConvertSidToStringSidA(s:*const u8,o:*mut *mut u8)->i32;
    fn LocalFree(h:isize)->isize;
}
fn main(){ unsafe{
    let pid:u32=std::env::args().nth(1).unwrap().parse().unwrap();
    let ph=OpenProcess(0x0400,0,pid); if ph==0 {println!("openprocess fail");return;}
    let mut th=0isize;
    if OpenProcessToken(ph,8,&mut th)!=0 {
        let mut buf=[0usize;16]; let mut rl=0u32;
        // TokenAppContainerSid=31, TokenIsAppContainer=29
        if GetTokenInformation(th,31,buf.as_mut_ptr() as *mut u8,128,&mut rl)!=0 {
            // buf is TOKEN_APPCONTAINER_INFORMATION — read the PSID it holds.
            let psid=buf[0];
            let mut o:*mut u8=std::ptr::null_mut();
            if ConvertSidToStringSidA(psid as *const u8,&mut o)!=0 {
                println!("AC_SID={}",std::ffi::CStr::from_ptr(o as *const i8).to_str().unwrap()); LocalFree(o as isize); }
        }
        let mut v=[0u8;4]; let mut rl2=0u32;
        if GetTokenInformation(th,29,v.as_mut_ptr(),4,&mut rl2)!=0 { println!("IS_AC={}",v[0]); }
        CloseHandle(th);
    }
    CloseHandle(ph);
}}
