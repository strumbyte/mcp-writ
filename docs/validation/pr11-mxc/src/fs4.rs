use std::fs;
fn r(l:&str,p:&str){match fs::read(p){Ok(b)=>println!("{l} {p} -> ok {}B",b.len()),Err(e)=>println!("{l} {p} -> err {}",e.raw_os_error().unwrap_or(-1))}}
fn e(p:&str){match fs::read_dir(p){Ok(mut i)=>println!("enum {p} -> ok {}",i.by_ref().take(3).count()),Err(x)=>println!("enum {p} -> err {}",x.raw_os_error().unwrap_or(-1))}}
fn main(){
    e("D:\\");
    r("dfile","D:\\Projects\\mcp-writ\\Cargo.toml");
    e("D:\\Projects\\mcp-writ");
    r("shadow","C:\\Windows\\System32\\config\\SECURITY");
}
