use std::fs;
fn r(l:&str,p:&str){match fs::read(p){Ok(b)=>println!("{l} {p} -> ok {}B",b.len()),Err(e)=>println!("{l} {p} -> err {}",e.raw_os_error().unwrap_or(-1))}}
fn e(p:&str){match fs::read_dir(p){Ok(mut i)=>println!("enum {p} -> ok {}",i.by_ref().take(3).count()),Err(x)=>println!("enum {p} -> err {}",x.raw_os_error().unwrap_or(-1))}}
fn main(){
    let h=std::env::var("USERPROFILE").unwrap_or("C:\\Users\\x".into());
    r("desktop",&format!("{}\\Desktop\\desktop.ini",h));
    e(&format!("{}\\Desktop",h));
    e(&h);
    r("ntuser",&format!("{}\\NTUSER.DAT",h));
    let u=std::env::var("USERNAME").unwrap_or("probe.user".into());
    let j=std::env::args().nth(1).unwrap_or_default();
    r("junc",&format!("{}\\Public\\desktop.ini",j));
    e(&format!("{}\\{}",j,u));
    r("junc2",&format!("{}\\{}\\NTUSER.DAT",j,u));
}
