//! Windows/WSL probe stub for PR-27 `plan` diagnostics e2e.
//!
//! One std-only binary plays every probed CLI. It dispatches on its own
//! file name — copies are placed as `wslc.exe`, `powershell.exe`,
//! `reg.exe`, and `wsl.exe` (`wslc` is checked before `wsl` because the
//! former contains the latter) — and answers from `scenario.txt` in the
//! executable's directory. Every invocation appends `<stem>\t<args>` to
//! `calls.txt` next to the exe, so a test can prove exactly which
//! probes ran — or that none did.
//!
//! `scenario.txt` is split into `=== <key> ===` sections; the text
//! under a header is the payload the role emits. Extras:
//!
//!   <key>.exit — a nonzero integer; the payload goes to stderr and the
//!                process exits with that code
//!   <key>.utf16 — `1` emits the payload as UTF-16LE with a BOM
//!   <key>.flood — `1` writes the payload to stdout forever, blocking
//!                once the pipe is full — the probe's output cap must
//!                kill it rather than wait the deadline out
//!
//! Keys the probe layer issues:
//!   `wsl.exe --version`        → `wsl.version`
//!   `wsl.exe -l -v`            → `wsl.list`
//!   `wslc.exe --version`       → `wslc.version`
//!   `reg.exe query …`          → `reg.query`
//!   `powershell.exe -Command …` → `pwsh.package`
//!
//! A missing section answers empty output with exit 0 — an "answered
//! but empty" case a parser must not read facts from.

use std::io::Write;
use std::path::PathBuf;

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn stem() -> String {
    std::env::current_exe()
        .unwrap()
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_lowercase()
}

/// Split the scenario file into `=== name ===` sections.
fn sections(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut name: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        if let Some(inner) = line
            .strip_prefix("=== ")
            .and_then(|l| l.strip_suffix(" ==="))
        {
            if let Some(prev) = name.take() {
                out.push((prev, std::mem::take(&mut body)));
            }
            name = Some(inner.trim().to_string());
        } else if name.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(prev) = name {
        out.push((prev, body));
    }
    out
}

fn section<'a>(sections: &'a [(String, String)], key: &str) -> Option<&'a str> {
    sections
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn main() {
    let dir = exe_dir();
    let stem = stem();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls.txt"))
        .unwrap();
    writeln!(log, "{stem}\t{}", args.join(" ")).unwrap();
    drop(log);

    let scenario = std::fs::read_to_string(dir.join("scenario.txt")).unwrap_or_default();
    let sections = sections(&scenario);

    let key = if stem.contains("wslc") {
        match args.first().map(String::as_str) {
            Some("--version") | Some("version") => "wslc.version",
            _ => {
                eprintln!("stub: unhandled wslc args {args:?}");
                std::process::exit(3);
            }
        }
    } else if stem.contains("powershell") || stem.contains("pwsh") {
        "pwsh.package"
    } else if stem == "reg" {
        "reg.query"
    } else if stem.contains("wsl") {
        match args.first().map(String::as_str) {
            Some("--version") => "wsl.version",
            Some("-l") | Some("--list") => "wsl.list",
            _ => {
                eprintln!("stub: unhandled wsl args {args:?}");
                std::process::exit(3);
            }
        }
    } else {
        eprintln!("stub: unknown role for exe name '{stem}'");
        std::process::exit(3);
    };

    let payload = section(&sections, key).unwrap_or("").to_string();
    let exit_code = section(&sections, &format!("{key}.exit"))
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(0);
    let utf16 =
        section(&sections, &format!("{key}.utf16")).is_some_and(|v| v.trim() == "1");

    if exit_code != 0 {
        // A failing CLI reports on stderr (inbox `wsl --version`,
        // disabled-feature errors) — the probe records it in the
        // failure detail.
        eprint!("{payload}");
        std::process::exit(exit_code);
    }
    let flood = section(&sections, &format!("{key}.flood")).is_some_and(|v| v.trim() == "1");
    if flood {
        // Keep writing until the reader goes away — a broken pipe /
        // SIGPIPE ends the loop. With nobody draining, this blocks on
        // a full pipe buffer: the exact pathology the cap must kill.
        let chunk = if payload.is_empty() { "x" } else { &payload };
        let mut stdout = std::io::stdout().lock();
        while stdout.write_all(chunk.as_bytes()).is_ok() {}
        return;
    }
    if utf16 {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in payload.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::io::stdout().write_all(&bytes).unwrap();
    } else {
        print!("{payload}");
    }
}
