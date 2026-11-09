use std::fs;
fn try_read(label:&str, p:&str){
    match fs::read(p){ Ok(b)=>println!("{label} {p} -> ok {}B",b.len()), Err(e)=>println!("{label} {p} -> err {}",e.raw_os_error().unwrap_or(-1)) }
}
fn try_enum(p:&str){
    match fs::read_dir(p){ Ok(mut i)=>println!("enum {p} -> ok {} entries", i.by_ref().take(5).count()), Err(e)=>println!("enum {p} -> err {}",e.raw_os_error().unwrap_or(-1)) }
}
fn main(){
    // default-deny semantics: ungranted system/user paths
    try_read("sysfile","C:\\Windows\\win.ini");
    try_read("sysdll","C:\\Windows\\System32\\kernel32.dll");
    try_read("windir","C:\\Windows\\notepad.exe");
    try_read("userprof","C:\\Users\\Public\\desktop.ini");
    try_read("reg?","C:\\Windows\\System32\\drivers\\etc\\hosts");
    try_enum("C:\\Windows");
    try_enum("C:\\Users");
    try_enum("C:\\");
    // bypass vectors on a DENIED path (arg0 = denied file)
    if let Some(d)=std::env::args().nth(1){
        try_read("deny-direct",&d);
        try_read("deny-unc", &format!("\\\\?\\{}",d));
        try_read("deny-ads", &format!("{}:stream",d));
        try_read("deny-fw", &d.replace('\\',"/"));
    }
    // ungranted under granted parent vs sibling
    if let Some(g)=std::env::args().nth(2){ try_read("under-grant",&format!("{}\\..\\ungranted\\ungranted.txt",g)); }
}
