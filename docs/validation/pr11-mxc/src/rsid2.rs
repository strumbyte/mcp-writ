#[link(name="kernel32")] extern "system" { fn GetCurrentProcess()->isize; fn GetLastError()->u32; fn CloseHandle(h:isize)->i32; }
#[link(name="advapi32")] extern "system" {
    fn OpenProcessToken(p:isize,a:u32,h:*mut isize)->i32;
    fn GetTokenInformation(h:isize,c:u32,i:*mut u8,l:u32,r:*mut u32)->i32;
    fn ConvertSidToStringSidA(s:*const u8,o:*mut *mut u8)->i32;
    fn LocalFree(h:isize)->isize;
}
fn main(){ unsafe{
    let mut th=0isize;
    let r0=OpenProcessToken(GetCurrentProcess(),8,&mut th);
    println!("open_token rc={r0} err={}",GetLastError());
    if r0!=0 {
        for cls in [29u32,31u32] {
            let mut buf=[0usize;32]; let mut rl=0u32;
            let r=GetTokenInformation(th,cls,buf.as_mut_ptr() as *mut u8,256,&mut rl);
            println!("class={cls} rc={r} err={} need={rl}",GetLastError());
            if r!=0 && cls==31 {
                // buf is TOKEN_APPCONTAINER_INFORMATION — read the PSID it holds.
                let psid=buf[0];
                let mut o:*mut u8=std::ptr::null_mut();
                if ConvertSidToStringSidA(psid as *const u8,&mut o)!=0 {
                    println!("AC_SID={}",std::ffi::CStr::from_ptr(o as *const i8).to_str().unwrap()); LocalFree(o as isize); }
            }
            if r!=0 && cls==29 { println!("IS_AC={}",buf[0]); }
        }
        CloseHandle(th);
    }
}}
