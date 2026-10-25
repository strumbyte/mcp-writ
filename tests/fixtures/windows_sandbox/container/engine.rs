// std-only stand-in for `src/container/engine.rs`'s
// `bounded_driver_output` inside the plain-rustc fixture crate: the
// shipped engine pulls in the whole container backend graph, which the
// rustc fixture build cannot see. Same contract for the agent's
// best-effort `netsh` leg — bounded wait, concurrent pipe drains so a
// flooded stderr cannot deadlock the probe, capped output, killed and
// reaped on timeout, CREATE_NO_WINDOW so the console-attached agent
// never pops a window. The stand-in `BoundDriver` performs no identity
// re-verification (no windows crates here); the shipped one does.

use std::process::{Output, Stdio};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
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

/// [`bounded_driver_output`] on a bound driver — same signature as the
/// shipped helper; `std_command` is where the real identity
/// re-verification lives (the fixture stand-in just builds the command).
pub(crate) fn bounded_driver_output(
    driver: &crate::trusted_path::BoundDriver,
    args: &[&str],
) -> std::io::Result<Output> {
    let mut cmd = driver.std_command()?;
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
    // Same contract as the shipped engine: the drain budget is measured
    // from the observed exit, not from spawn — a CLI answering just inside
    // the probe deadline must not leave zero time for pipe collection.
    let drain_deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
    let collect = |rx: std::sync::mpsc::Receiver<Vec<u8>>| -> std::io::Result<Vec<u8>> {
        match rx
            .recv_timeout(drain_deadline.saturating_duration_since(std::time::Instant::now()))
        {
            Ok(buf) => Ok(buf),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "pipe held open past the {}s drain deadline",
                    DRAIN_TIMEOUT.as_secs()
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
