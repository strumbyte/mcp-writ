// std-only stand-in for `src/container/engine.rs`'s
// `bounded_cli_output` inside the plain-rustc fixture crate: the
// shipped engine pulls in the whole container backend graph, which the
// rustc fixture build cannot see. Same contract for the agent's
// best-effort `netsh` leg — bounded wait, concurrent pipe drains so a
// flooded stderr cannot deadlock the probe, capped output, killed and
// reaped on timeout, CREATE_NO_WINDOW so the console-attached agent
// never pops a window.

use std::process::{Command as StdCommand, Output, Stdio};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const OUTPUT_CAP: u64 = 64 * 1024;

fn drain_pipe(
    pipe: Option<impl std::io::Read + Send + 'static>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    use std::io::Read;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(s) = pipe {
            let _ = s.take(OUTPUT_CAP).read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

pub(crate) fn bounded_cli_output(
    prog: &str,
    args: &[&str],
) -> std::io::Result<Output> {
    let mut cmd = StdCommand::new(prog);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn()?;
    let out_rx = drain_pipe(child.stdout.take());
    let err_rx = drain_pipe(child.stderr.take());
    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no answer within {}s", PROBE_TIMEOUT.as_secs()),
                ));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| -> std::io::Result<Vec<u8>> {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(buf) => Ok(buf),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "pipe held open past the {}s deadline",
                    PROBE_TIMEOUT.as_secs()
                ),
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(std::io::Error::other("pipe reader died"))
            }
        }
    };
    Ok(Output {
        status,
        stdout: collect(out_rx)?,
        stderr: collect(err_rx)?,
    })
}
