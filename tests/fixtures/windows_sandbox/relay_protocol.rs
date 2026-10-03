//! Shared, bounded transport for the PR-23 prototype (also built by rustc).
#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const F_HELLO: u8 = 1;
pub const F_HELLO_ACK: u8 = 2;
pub const F_STDIN: u8 = 3;
pub const F_STDIN_EOF: u8 = 4;
pub const F_STDOUT: u8 = 5;
pub const F_STDERR: u8 = 6;
pub const F_EXIT: u8 = 7;
pub const F_AGENT_ERROR: u8 = 8;
pub const F_PEER: u8 = 9;
pub const F_CANCEL: u8 = 10;
pub const MAX_FRAME: usize = 1024 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);
pub const POLL: Duration = Duration::from_millis(100);

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "relay frame deadline exceeded"))
}

/// One deadline covers the whole frame, including a peer accepting tiny writes.
pub fn write_frame(conn: &mut TcpStream, kind: u8, payload: &[u8]) -> io::Result<()> {
    write_frame_until(conn, kind, payload, Instant::now() + IO_TIMEOUT)
}

pub fn write_frame_until(
    conn: &mut TcpStream,
    kind: u8,
    payload: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(invalid("frame exceeds 1 MiB cap"));
    }
    let deadline = deadline.min(Instant::now() + IO_TIMEOUT);
    let mut header = [kind, 0, 0, 0, 0];
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    for mut bytes in [&header[..], payload] {
        while !bytes.is_empty() {
            conn.set_write_timeout(Some(remaining(deadline)?))?;
            match conn.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Poll timeouts retain both header and payload offsets. Idle connections have
/// no deadline; a partial frame must finish within IO_TIMEOUT, regardless of
/// trickle traffic. Callers can impose a shorter handshake/session deadline.
#[derive(Default)]
pub struct FrameReader {
    header: [u8; 5],
    header_len: usize,
    payload: Vec<u8>,
    payload_len: usize,
    deadline: Option<Instant>,
}

impl FrameReader {
    pub fn poll(&mut self, conn: &mut TcpStream) -> io::Result<Option<(u8, Vec<u8>)>> {
        loop {
            let timeout = self.deadline.map(remaining).transpose()?.unwrap_or(POLL);
            conn.set_read_timeout(Some(timeout.min(POLL)))?;
            if self.header_len == 5 && self.payload_len == self.payload.len() {
                let kind = self.header[0];
                let payload = std::mem::take(&mut self.payload);
                self.header_len = 0;
                self.payload_len = 0;
                self.deadline = None;
                return Ok(Some((kind, payload)));
            }
            let header = self.header_len < 5;
            let bytes = if header {
                &mut self.header[self.header_len..]
            } else {
                &mut self.payload[self.payload_len..]
            };
            match conn.read(bytes) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    self.deadline
                        .get_or_insert_with(|| Instant::now() + IO_TIMEOUT);
                    if header {
                        self.header_len += n;
                        if self.header_len == 5 {
                            let len =
                                u32::from_be_bytes(self.header[1..].try_into().unwrap()) as usize;
                            if len > MAX_FRAME {
                                return Err(invalid("frame exceeds 1 MiB cap"));
                            }
                            self.payload.resize(len, 0);
                        }
                    } else {
                        self.payload_len += n;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

pub fn read_frame(conn: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    read_frame_until(conn, Instant::now() + IO_TIMEOUT)
}

pub fn read_frame_until(conn: &mut TcpStream, deadline: Instant) -> io::Result<(u8, Vec<u8>)> {
    let mut reader = FrameReader {
        deadline: Some(deadline),
        ..FrameReader::default()
    };
    loop {
        remaining(deadline)?;
        if let Some(frame) = reader.poll(conn)? {
            return Ok(frame);
        }
    }
}

/// This private wire protocol requires canonical ASCII JSON. Comparing the
/// entire message rejects wrong versions, duplicate keys and trailing input.
pub fn hello(launch_id: &str, token: &str) -> String {
    format!("{{\"v\":1,\"launch_id\":\"{launch_id}\",\"token\":\"{token}\"}}")
}

pub fn ack(launch_id: &str) -> String {
    format!("{{\"v\":1,\"launch_id\":\"{launch_id}\",\"agent\":\"wsb-relay-agent\"}}")
}
