use std::fs;
fn r(l:&str,p:&str){match fs::read(p){Ok(b)=>println!("{l} {p} -> ok {}B",b.len()),Err(e)=>println!("{l} {p} -> err {}",e.raw_os_error().unwrap_or(-1))}}
fn e(p:&str){match fs::read_dir(p){Ok(mut i)=>println!("enum {p} -> ok {}",i.by_ref().take(3).count()),Err(x)=>println!("enum {p} -> err {}",x.raw_os_error().unwrap_or(-1))}}
fn main(){
    let home=std::env::var("USERPROFILE").unwrap_or("C:\\Users\\x".into());
    r("desktop",&format!("{}\\Desktop\\desktop.ini",home));
    e(&format!("{}\\Desktop",home));
    e(&format!("{}\\Documents",home));
    e(&home);
    r("pf","C:\\Program Files\\desktop.ini");
    e("C:\\Program Files");
    r("progdata","C:\\ProgramData\\desktop.ini");
    e("C:\\ProgramData");
    r("ungranted", &format!("{}\\ungranted.txt", std::env::args().nth(1).unwrap_or("C:\\nonexist".into())));
    r("sam","C:\\Windows\\System32\\config\\SAM");
    r("secr","C:\\Windows\\security\\database\\secedit.sdb");
}
