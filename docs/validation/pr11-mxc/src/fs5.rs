// fs normalization bypass battery: case, 8.3, trailing dot/space, fwd slash, .\ comp
// args: <denied_file> <denied_dir_8.3> <denied_dir>
use std::ffi::OsStr;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        n: *const u16, a: u32, s: u32, sa: *mut core::ffi::c_void, c: u32, f: u32, t: isize,
    ) -> isize;
    fn GetLastError() -> u32;
    fn CloseHandle(h: isize) -> i32;
    fn GetShortPathNameW(l: *const u16, s: *mut u16, c: u32) -> u32;
    fn FindFirstFileW(n: *const u16, d: *mut u8) -> isize;
    fn FindClose(h: isize) -> i32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn open(p: &str) -> String {
    let h = unsafe { CreateFileW(w(p).as_ptr(), 0x80000000, 7, core::ptr::null_mut(), 3, 0, 0) };
    if h == -1 {
        return format!("err:{}", unsafe { GetLastError() });
    }
    unsafe { CloseHandle(h) };
    "OPEN-OK".into()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let file = &a[0]; // e.g. C:\scratch\fs5\secret.txt (denied dir)
    let dir83 = &a[1]; // 8.3 name of denied dir, e.g. C:\scratch\FS5~1
    let dir = &a[2]; // denied dir normal path

    // baseline
    println!("normal           {file} -> {}", open(file));
    // case variants — fs is case-insensitive; is the deny matcher?
    let upper = file.to_uppercase();
    println!("upper            {upper} -> {}", open(&upper));
    let mixed: String = file
        .chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
        .collect();
    println!("mixed            {mixed} -> {}", open(&mixed));
    // 8.3 short name of denied dir
    let p83 = format!("{dir83}\\{}", file.rsplit('\\').next().unwrap());
    println!("8.3 dir          {p83} -> {}", open(&p83));
    // also ask OS what the short name really is
    let mut buf = [0u16; 512];
    let n = unsafe { GetShortPathNameW(w(dir).as_ptr(), buf.as_mut_ptr(), 512) };
    let sn = String::from_utf16_lossy(&buf[..n as usize]);
    println!("os shortname     {dir} => {sn}");
    if !sn.is_empty() {
        let p = format!("{sn}\\{}", file.rsplit('\\').next().unwrap());
        println!("8.3 os           {p} -> {}", open(&p));
    }
    // trailing dot / space (Windows strips them at normalize)
    let pd = format!("{file}.");
    println!("trailing dot     {pd} -> {}", open(&pd));
    let ps = format!("{file} ");
    println!("trailing space   {ps} -> {}", open(&ps));
    // forward slashes
    let pf = file.replace('\\', "/");
    println!("fwd slash        {pf} -> {}", open(&pf));
    // .\ component inside denied dir
    let pdot = file.replace("fs5\\", "fs5\\.\\");
    println!("dot comp         {pdot} -> {}", open(&pdot));
    // denied dir itself via .\ child
    let dchild = format!("{dir}\\.\\x.txt");
    println!("dir dotchild     {dchild} -> {}", open(&dchild));
    // NT-style \??\ prefix
    let pnt = format!("\\??\\{file}");
    println!("nt prefix        {pnt} -> {}", open(&pnt));
    // UNC local
    let punc = file.replace("C:\\", "\\\\?\\UNC\\localhost\\c$\\");
    println!("unc local        {punc} -> {}", open(&punc));
}
