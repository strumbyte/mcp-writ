#[link(name="kernel32")] extern "system" { fn GetCurrentProcess()->isize; fn CloseHandle(h:isize)->i32; }
#[link(name="advapi32")] extern "system" {
    fn OpenProcessToken(p:isize,a:u32,h:*mut isize)->i32;
    fn GetTokenInformation(h:isize,c:u32,i:*mut u8,l:u32,r:*mut u32)->i32;
    fn ConvertSidToStringSidA(s:*const u8,o:*mut *mut u8)->i32;
    fn LocalFree(h:isize)->isize;
}
fn main(){ unsafe{
    let mut th=0isize;
    OpenProcessToken(GetCurrentProcess(),8,&mut th);
    let mut buf=[0usize;32]; let mut rl=0u32;
    if GetTokenInformation(th,31,buf.as_mut_ptr() as *mut u8,256,&mut rl)!=0 {
        let psid=buf[0];
        let mut o:*mut u8=std::ptr::null_mut();
        if ConvertSidToStringSidA(psid as *const u8,&mut o)!=0 {
            let s=std::ffi::CStr::from_ptr(o as *const i8).to_str().unwrap_or("?").to_string();
            println!("AC_SID={s}");
            let sf=std::env::args().nth(1);
            if let Some(f)=sf { std::fs::write(f,format!("AC_SID={s}\n")).ok(); }
            LocalFree(o as isize);
        } else { println!("sid conv fail"); }
    }
    CloseHandle(th);
}}
