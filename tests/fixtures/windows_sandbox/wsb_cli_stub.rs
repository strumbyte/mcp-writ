//! Management contract fixture: records IDs even when start fails or times out.
use std::io::Write;

fn main() {
    let dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("calls.txt"))
        .unwrap();
    writeln!(log, "{}", args.join("\t")).unwrap();
    let id = args
        .windows(2)
        .find(|w| w[0] == "--id")
        .map(|w| w[1].as_str())
        .unwrap_or("");
    match args.first().map_or("", String::as_str) {
        "list" => {
            let ids = std::fs::read_to_string(dir.join("ids.txt"))
                .unwrap_or_else(|_| "{\"WindowsSandboxEnvironments\":[]}".into());
            println!("{ids}");
        }
        "start" => {
            if args.iter().any(|a| a == "wrong-id") {
                // Start returned success without publishing the reserved ID.
                std::fs::write(dir.join("ids.txt"), "{\"WindowsSandboxEnvironments\":[]}").unwrap();
                return;
            }
            std::fs::write(
                dir.join("ids.txt"),
                format!("{{\"WindowsSandboxEnvironments\":[{{\"Id\":\"{id}\"}}]}}"),
            )
            .unwrap();
            if args.iter().any(|a| a == "fail") {
                std::process::exit(42);
            }
            if args.iter().any(|a| a == "timeout") {
                std::thread::sleep(std::time::Duration::from_secs(120));
            }
        }
        "connect" => std::thread::sleep(std::time::Duration::from_secs(120)),
        "stop" => {
            std::fs::write(dir.join("ids.txt"), "{\"WindowsSandboxEnvironments\":[]}").unwrap();
        }
        _ => std::process::exit(1),
    }
}
