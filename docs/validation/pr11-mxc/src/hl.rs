// fs bypass probe: hardlink / symlink / GLOBALROOT / PhysicalDrive / exec-written-exe
// args: <writable_dir> <denied_file>
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;

#[link(name = "kernel32")]
extern "system" {
    fn CreateHardLinkW(
        lpFileName: *const u16,
        lpExistingFileName: *const u16,
        lpSecurityAttributes: *mut core::ffi::c_void,
    ) -> i32;
    fn CreateSymbolicLinkW(
        lpSymlinkFileName: *const u16,
        lpTargetFileName: *const u16,
        dwFlags: u32,
    ) -> u8;
    fn GetLastError() -> u32;
}

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn try_read(p: &str, label: &str) {
    match fs::read(p) {
        Ok(d) => println!("{label}: ok {}B", d.len()),
        Err(e) => println!("{label}: err:{}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let wdir = &a[1];
    let denied = &a[2];
    let _ = fs::create_dir_all(wdir);

    // 1. hardlink to a denied file from a writable dir — classic link bypass
    let link = format!("{wdir}\\hl-deny.txt");
    let r = unsafe { CreateHardLinkW(w(&link).as_ptr(), w(denied).as_ptr(), core::ptr::null_mut()) };
    println!("hardlink create -> r={} err={}", r, unsafe { GetLastError() });
    if r != 0 {
        try_read(&link, "hardlink read");
        match fs::write(&link, b"x") {
            Ok(_) => println!("hardlink write: ok (BYPASS)"),
            Err(e) => println!("hardlink write: err:{}", e.raw_os_error().unwrap_or(-1)),
        }
    }

    // 2. symlink (requires SeCreateSymbolicLinkPrivilege — expect 1314)
    let slink = format!("{wdir}\\sl-deny.txt");
    let r2 = unsafe { CreateSymbolicLinkW(w(&slink).as_ptr(), w(denied).as_ptr(), 0) };
    println!("symlink create -> r={} err={}", r2, unsafe { GetLastError() });
    if r2 != 0 {
        try_read(&slink, "symlink read");
    }

    // 3. GLOBALROOT device namespace — alternate path to same objects
    try_read(r"\\?\GLOBALROOT\DosDevices\C:\Windows\win.ini", "globalroot C: win.ini");
    let gr_denied = format!(
        r"\\?\GLOBALROOT\DosDevices\{}",
        denied.replace('/', "\\")
    );
    try_read(&gr_denied, "globalroot denied file");
    try_read(
        r"\\?\GLOBALROOT\DosDevices\C:\Users\Public\desktop.ini",
        "globalroot public",
    );

    // 4. raw device objects
    match fs::File::open(r"\\.\PhysicalDrive0") {
        Ok(_) => println!("PhysicalDrive0: OPENED (raw disk readable)"),
        Err(e) => println!("PhysicalDrive0: err:{}", e.raw_os_error().unwrap_or(-1)),
    }
    match fs::read(r"\\?\GLOBALROOT\Device\Harddisk0\Partition0") {
        Ok(d) => println!("Harddisk0Partition0: ok {}B", d.len()),
        Err(e) => println!("Harddisk0Partition0: err:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // 5a. baseline: exec the real System32 whoami (unmodified, ambient path)
    match std::process::Command::new(r"C:\Windows\System32\whoami.exe")
        .arg("/all")
        .output()
    {
        Ok(o) => println!(
            "exec system whoami: code={} out={}",
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).trim().chars().take(80).collect::<String>()
        ),
        Err(e) => println!("exec system whoami: err:{} {}", e.raw_os_error().unwrap_or(-1), e),
    }

    // 5b. write a new exe into the writable dir and execute it
    let dst = format!("{wdir}\\written-whoami.exe");
    match fs::copy(r"C:\Windows\System32\whoami.exe", &dst) {
        Ok(_) => {
            println!("copy whoami -> ok");
            match std::process::Command::new(&dst).output() {
                Ok(o) => println!(
                    "exec written exe: code={} out={}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stdout).trim().chars().take(80).collect::<String>()
                ),
                Err(e) => println!("exec written exe: err:{} {}", e.raw_os_error().unwrap_or(-1), e),
            }
        }
        Err(e) => println!("copy whoami: err:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // 5c. exec a user32-free exe (findstr) written into the writable dir
    let dst2 = format!("{wdir}\\written-findstr.exe");
    match fs::copy(r"C:\Windows\System32\findstr.exe", &dst2) {
        Ok(_) => match std::process::Command::new(&dst2).arg("/?").output() {
            Ok(o) => println!(
                "exec written findstr: code={} out={}",
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).chars().take(60).collect::<String>()
            ),
            Err(e) => println!("exec written findstr: err:{}", e.raw_os_error().unwrap_or(-1)),
        },
        Err(e) => println!("copy findstr: err:{}", e.raw_os_error().unwrap_or(-1)),
    }
    // 5d. direct exec of system findstr (baseline path, no user32)
    match std::process::Command::new(r"C:\Windows\System32\findstr.exe")
        .arg("/?")
        .output()
    {
        Ok(o) => println!("exec system findstr: code={}", o.status.code().unwrap_or(-1)),
        Err(e) => println!("exec system findstr: err:{}", e.raw_os_error().unwrap_or(-1)),
    }
}
