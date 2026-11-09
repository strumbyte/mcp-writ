use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

fn drain<T: Read + Send + 'static>(mut s: T, tx: mpsc::Sender<u8>) {
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        loop {
            match s.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = tx.send(b[0]);
                }
            }
        }
    });
}

fn main() {
    let json_path = std::env::args().nth(1).expect("json path");
    let secs: u64 = std::env::args().nth(2).unwrap_or("30".into()).parse().unwrap();
    let json = std::fs::read_to_string(&json_path).expect("read json");
    match mxc_sdk::__ffi::spawn_container_json(&json, false) {
        Ok(mut p) => {
            let (txo, rxo) = mpsc::channel::<u8>();
            let (txe, rxe) = mpsc::channel::<u8>();
            if let Some(o) = p.take_stdout() {
                drain(o, txo);
            }
            if let Some(e) = p.take_stderr() {
                drain(e, txe);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut st = None;
            while std::time::Instant::now() < deadline {
                while let Ok(c) = rxo.try_recv() {
                    out.push(c);
                }
                while let Ok(c) = rxe.try_recv() {
                    err.push(c);
                }
                if let Some(s) = p.try_wait().ok().flatten() {
                    st = Some(s);
                    std::thread::sleep(Duration::from_millis(250));
                    while let Ok(c) = rxo.try_recv() {
                        out.push(c);
                    }
                    while let Ok(c) = rxe.try_recv() {
                        err.push(c);
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if st.is_none() {
                p.kill().ok();
            }
            print!("stdout<<{}", String::from_utf8_lossy(&out));
            print!("stderr<<{}", String::from_utf8_lossy(&err));
            println!("exit={st:?}");
        }
        Err(e) => println!("spawn error: {e:?}"),
    }
}
