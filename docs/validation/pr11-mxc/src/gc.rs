use std::io::Read;

// Runs as the container child; spawns a GRANDCHILD winiso battery and
// relays its fs/net results so we can check whether the container's
// restrictions are inherited by descendants.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exe = &args[0];
    let rest = &args[1..];
    let mut c = match std::process::Command::new(exe)
        .args(rest)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            println!("gc_spawn -> err {e}");
            return;
        }
    };
    let mut out = String::new();
    if let Some(mut so) = c.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    let st = c.wait().map(|s| s.code()).unwrap_or(None);
    println!("gc_exit={:?}", st);
    // Extract just the security-relevant ops from the grandchild's JSON.
    for probe in [
        "fs_read_deny", "fs_write_deny", "fs_write_ro", "fs_read_ungranted",
        "reg_write_hklm", "net_connect_allow", "net_connect_deny",
        "is_appcontainer", "integrity_level",
    ] {
        if let Some(i) = out.find(probe) {
            let seg = &out[i..];
            let end = seg.find('}').map(|e| e + 1).unwrap_or(seg.len().min(160));
            println!("GC| {}", &seg[..end.min(200)]);
        }
    }
}
