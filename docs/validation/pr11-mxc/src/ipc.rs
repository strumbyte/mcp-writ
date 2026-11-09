use std::os::windows::ffi::OsStrExt; use std::ffi::OsStr;
#[link(name="kernel32")] extern "system" {
    fn OpenProcess(a:u32,b:i32,c:u32)->isize; fn CloseHandle(h:isize)->i32;
    fn K32EnumProcesses(p:*mut u32,cb:u32,need:*mut u32)->i32;
    fn GetCurrentProcessId()->u32;
}
#[link(name="advapi32")] extern "system" {
    fn RegOpenKeyExW(h:isize,s:*const u16,r:u32,a:u32,o:*mut isize)->i32;
    fn RegCloseKey(h:isize)->i32;
    fn OpenProcessToken(p:isize,a:u32,h:*mut isize)->i32;
    fn GetTokenInformation(h:isize,c:u32,i:*mut u8,l:u32,r:*mut u32)->i32;
    fn GetCurrentProcess()->isize;
}
fn w(s:&str)->Vec<u16>{OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()}
fn main(){
    unsafe{
        let mut pids=[0u32;4096]; let mut need=0u32;
        let ok=K32EnumProcesses(pids.as_mut_ptr(),4096*4,&mut need);
        println!("enum_processes ok={} count={}",ok,if ok!=0 {need/4} else {0});
        let me=GetCurrentProcessId();
        let mut openable=0; let total=(need/4).min(4096);
        for &p in pids.iter().take(total as usize){ if p==me||p==0 {continue}
            let h=OpenProcess(0x0400/*QUERY_INFORMATION*/,0,p); if h!=0 {openable+=1;CloseHandle(h);} }
        println!("openable_host_processes={openable} of {total}");
        // token privileges: TokenPrivileges(3)
        let mut th=0isize;
        if OpenProcessToken(GetCurrentProcess(),8,&mut th)!=0 {
            let mut buf=[0u8;1024]; let mut rl=0u32;
            let g=GetTokenInformation(th,3,buf.as_mut_ptr(),1024,&mut rl);
            let cnt=if g!=0 {u32::from_le_bytes([buf[0],buf[1],buf[2],buf[3]])} else {0};
            println!("token_privilege_count={cnt}");
            CloseHandle(th);
        }
        // HKCU read
        let mut k=0isize;
        let r=RegOpenKeyExW(0x80000001u32 as usize as isize,w("Environment").as_ptr(),0,0x20019,&mut k);
        println!("hkcu_environment_open rc={r}"); if r==0 {RegCloseKey(k);}
        let r2=RegOpenKeyExW(0x80000001u32 as usize as isize,w("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer").as_ptr(),0,0x20019,&mut k);
        println!("hkcu_explorer_open rc={r2}"); if r2==0 {RegCloseKey(k);}
    }
}
