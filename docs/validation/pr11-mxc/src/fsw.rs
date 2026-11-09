use std::fs; use std::io::Write;
fn w(p:&str){ match fs::File::create(p){ Ok(mut f)=>{ let r=f.write_all(b"x"); println!("write {p} -> {}",r.map(|_|"ok".to_string()).unwrap_or_else(|e|format!("err {}",e.raw_os_error().unwrap_or(-1)))) } Err(e)=>println!("create {p} -> err {}",e.raw_os_error().unwrap_or(-1)) } }
fn main(){ w("C:\\Windows\\Temp\\mxcprobe.tmp"); w("C:\\Users\\Public\\mxcprobe.tmp"); w("C:\\ProgramData\\mxcprobe.tmp");
    if let Some(d)=std::env::args().nth(1){ w(&format!("{}\\newfile.txt",d)); } }
