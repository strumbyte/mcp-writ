//! Ring-buffer drain — the userspace half of kernel-side deny
//! observation. `BPF_MAP_TYPE_RINGBUF` maps three regions through the
//! map fd: the consumer page (RW, offset 0), then the producer page
//! plus data (RO, offset `page_size`, length `page_size + 2*data`).
//!
//! Record framing: each record starts with a `u64` header whose low
//! u32 is `len | flags` (`BUSY` bit 31, `DISCARD` bit 30) and whose
//! high u32 is a page offset. Upstream kernels store
//! `round_up(payload + 8, 8)` in `len`; the consumer below accepts
//! either that form or a bare payload length — both resolve to the
//! same stride for the fixed-size event — and validates the record
//! magic before parsing.

use std::io;
use std::os::unix::io::RawFd;

use super::prog::{EVENT_MAGIC, EVENT_SIZE};

/// One parsed deny event.
#[derive(Debug, Clone)]
pub struct DenyEvent {
    /// Matched rule-map index, `RULE_IDX_NONE` for the default action,
    /// or `RULE_IDX_GRANT | n` (grants never deny — defensive decode).
    pub rule_idx: u32,
    /// `AF_INET`/`AF_INET6`.
    pub family: u32,
    /// `IPPROTO_*` from the socket (`ctx->protocol`).
    pub proto: u32,
    /// Destination words in ctx byte order ([0] for v4).
    pub addr: [u32; 4],
    /// Raw `ctx->user_port` (`htons(port)` in the low bytes).
    pub port_raw: u32,
    /// `bpf_get_current_pid_tgid` — tgid in the high half.
    pub pid_tgid: u64,
}

impl DenyEvent {
    /// Host-order destination port.
    pub fn port(&self) -> u16 {
        (self.port_raw as u16).to_be()
    }
    /// Destination as a displayable address.
    pub fn dest(&self) -> Option<std::net::IpAddr> {
        match self.family as i32 {
            f if f == libc::AF_INET => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                self.addr[0].to_ne_bytes(),
            ))),
            f if f == libc::AF_INET6 => {
                let mut o = [0u8; 16];
                for (i, w) in self.addr.iter().enumerate() {
                    o[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
                }
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)))
            }
            _ => None,
        }
    }
    /// Process id the kernel reported (tgid half of pid_tgid).
    pub fn pid(&self) -> u32 {
        (self.pid_tgid >> 32) as u32
    }
}

/// mmap'd ring buffer view over the events map fd.
pub struct RingBuf {
    _cons: Mmap,
    prod_data: Mmap,
    data_size: usize,
    page: usize,
}

struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// Safety: a `RingBuf` is moved into the single drain thread and only
// touched there — the raw mmap pointer is never shared.
unsafe impl Send for Mmap {}

impl Mmap {
    fn map(fd: RawFd, len: usize, offset: usize, writable: bool) -> io::Result<Self> {
        // Safety: standard mmap over the ringbuf map fd; `len`/`offset`
        // follow the kernel's documented layout.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                if writable {
                    libc::PROT_READ | libc::PROT_WRITE
                } else {
                    libc::PROT_READ
                },
                libc::MAP_SHARED,
                fd,
                offset as i64,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ptr: p.cast(), len })
    }
    fn as_u64(&self, at: usize) -> u64 {
        debug_assert!(at + 8 <= self.len);
        // Safety: bounds checked above; the mapping is live for `self`.
        unsafe { (self.ptr.add(at) as *const u64).read_volatile() }
    }
    /// Kernel→userspace read that must order after the producer's
    /// writes (Linux ringbuf doc: acquire the producer position; the
    /// record header is committed with a release store).
    fn as_u64_acquire(&self, at: usize) -> u64 {
        debug_assert!(at + 8 <= self.len);
        // Safety: `AtomicU64` shares `u64`'s layout; bounds checked;
        // the mapping is live for `self`.
        unsafe {
            (&*(self.ptr.add(at) as *const std::sync::atomic::AtomicU64))
                .load(std::sync::atomic::Ordering::Acquire)
        }
    }
    /// Kernel→userspace read of a single 4-byte field — the record
    /// header's `len|flags` word is committed by the producer with a
    /// release store, so acquire it alone without touching the
    /// adjacent `pgoff` half.
    fn as_u32_acquire(&self, at: usize) -> u32 {
        debug_assert!(at + 4 <= self.len);
        // Safety: `AtomicU32` shares `u32`'s layout; bounds checked;
        // the mapping is live for `self`.
        unsafe {
            (&*(self.ptr.add(at) as *const std::sync::atomic::AtomicU32))
                .load(std::sync::atomic::Ordering::Acquire)
        }
    }
    /// Userspace→kernel write that must publish our finished reads —
    /// release so the kernel never reclaims a record mid-read.
    fn write_u64_release(&self, at: usize, v: u64) {
        debug_assert!(at + 8 <= self.len);
        // Safety: consumer page is the writable mapping; `AtomicU64`
        // shares `u64`'s layout.
        unsafe {
            (&*(self.ptr.add(at) as *const std::sync::atomic::AtomicU64))
                .store(v, std::sync::atomic::Ordering::Release)
        }
    }
    fn bytes(&self, at: usize, len: usize) -> &[u8] {
        debug_assert!(at + len <= self.len);
        unsafe { std::slice::from_raw_parts(self.ptr.add(at), len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // Safety: `ptr`/`len` name the mapping created in `map`.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

impl RingBuf {
    /// Wrap a `BPF_MAP_TYPE_RINGBUF` fd of `data_size` payload bytes.
    pub fn open(events_fd: RawFd, data_size: usize) -> io::Result<Self> {
        let page = page_size();
        let cons = Mmap::map(events_fd, page, 0, true)?;
        let prod_data = Mmap::map(events_fd, page + 2 * data_size, page, false)?;
        Ok(Self {
            _cons: cons,
            prod_data,
            data_size,
            page,
        })
    }

    fn consumer_pos(&self) -> u64 {
        self._cons.as_u64(0)
    }
    fn producer_pos(&self) -> u64 {
        self.prod_data.as_u64_acquire(0)
    }
    fn commit(&self, new_pos: u64) {
        self._cons.write_u64_release(0, new_pos);
    }
    fn record(&self, off: usize, len: usize) -> &[u8] {
        // Data starts right after the producer page.
        self.prod_data.bytes(self.page + off, len)
    }

    /// Whether a record is pending.
    pub fn has_pending(&self) -> bool {
        self.consumer_pos() < self.producer_pos()
    }

    /// Pop one event, or `None` when the buffer is drained. `Err` marks
    /// a malformed/oversized record — the consumer still advances past
    /// it so a bad record cannot wedge the drain.
    pub fn pop(&mut self) -> Option<io::Result<DenyEvent>> {
        let cons = self.consumer_pos();
        let prod = self.producer_pos();
        if cons >= prod {
            return None;
        }
        let off = (cons & (self.data_size as u64 - 1)) as usize;
        // The producer commits the header's `len|flags` word with a
        // release store — acquire it so a non-BUSY read synchronizes
        // the payload.
        let len_field = self.prod_data.as_u32_acquire(self.page + off);
        let len = len_field & 0x3fff_ffff;
        let busy = len_field & (1 << 31) != 0;
        if busy {
            // Producer mid-write — retry next pass.
            return None;
        }
        // `len` semantics: canonical kernels store payload+8 rounded
        // up to 8; the observed WSL2 build stores the payload size.
        // Both decode to the same record footprint for a fixed-size
        // event — disambiguate against EVENT_SIZE.
        let payload_len = if len >= EVENT_SIZE + 8 {
            len as usize - 8
        } else {
            len as usize
        };
        let advance = ((payload_len + 8) + 7) & !7;
        let next = cons + advance as u64;
        if len_field & (1 << 30) != 0 {
            // DISCARD record — skip silently.
            self.commit(next);
            return Some(Err(io::Error::other("discarded ringbuf record")));
        }
        if payload_len < EVENT_SIZE as usize {
            self.commit(next);
            return Some(Err(io::Error::other(format!(
                "short ringbuf record (len {payload_len})"
            ))));
        }
        let rec = self.record(off + 8, EVENT_SIZE as usize);
        let ev = DenyEvent {
            rule_idx: u32::from_ne_bytes(rec[4..8].try_into().unwrap()),
            family: u32::from_ne_bytes(rec[8..12].try_into().unwrap()),
            proto: u32::from_ne_bytes(rec[12..16].try_into().unwrap()),
            addr: [
                u32::from_ne_bytes(rec[16..20].try_into().unwrap()),
                u32::from_ne_bytes(rec[20..24].try_into().unwrap()),
                u32::from_ne_bytes(rec[24..28].try_into().unwrap()),
                u32::from_ne_bytes(rec[28..32].try_into().unwrap()),
            ],
            port_raw: u32::from_ne_bytes(rec[32..36].try_into().unwrap()),
            pid_tgid: u64::from_ne_bytes(rec[40..48].try_into().unwrap()),
        };
        self.commit(next);
        let magic = u32::from_ne_bytes(rec[0..4].try_into().unwrap());
        if magic != EVENT_MAGIC {
            return Some(Err(io::Error::other(format!(
                "bad ringbuf record magic {magic:#x}"
            ))));
        }
        Some(Ok(ev))
    }
}

/// Poll the ringbuf fd until data is pending or `timeout` passes.
/// `Ok(true)` = data ready.
pub fn poll_ready(events_fd: RawFd, timeout: std::time::Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: events_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // Safety: `pfd` is a live one-element array.
    let r = unsafe { libc::poll(&mut pfd, 1, ms) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r > 0 && pfd.revents & libc::POLLIN != 0)
}

fn page_size() -> usize {
    // Safety: sysconf is always safe.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as usize } else { 4096 }
}
