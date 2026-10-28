//! MCP wire framing: initialize request envelopes, fixture argv
//! for the scripted stdio server, and ELF glibc-version probes.

use super::binaries::python3_script_argv;

// ─── MCP wire framing helpers ────────────────────────────────────────
// PR-10 wire enforcement: requests must correlate with responses, and a
// 2025-11-25 session must complete initialize → initialized before
// ordinary traffic. These constants/helpers keep each test's handshake
// identical.

/// 2025-11-25 `initialize` request with a fixed id (`"init"`).
pub const INIT_REQUEST: &str = concat!(
    r#"{"jsonrpc":"2.0","id":"init","method":"initialize","#,
    r#""params":{"protocolVersion":"2025-11-25","capabilities":{},"#,
    r#""clientInfo":{"name":"e2e-test","version":"0"}}}"#,
);

/// `notifications/initialized` completing the 2025 handshake.
pub const INITIALIZED_NOTIF: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;

/// `initialize` carrying client capabilities (e.g. `"sampling"` for
/// server→client request tests). `caps` is raw JSON object text.
pub fn init_request_with_caps(caps: &str) -> String {
    format!(
        concat!(
            r#"{{"jsonrpc":"2.0","id":"init","method":"initialize","#,
            r#""params":{{"protocolVersion":"2025-11-25","capabilities":{},"#,
            r#""clientInfo":{{"name":"e2e-test","version":"0"}}}}}}"#,
        ),
        caps,
    )
}

/// `_meta` block marking a 2026-07-28 request. `clientCapabilities` is a
/// required object on every 2026 request.
pub const META_2026: &str = concat!(
    r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","#,
    r#""io.modelcontextprotocol/clientCapabilities":{}}"#,
);

/// Argv for the scripted stdio fixture server in a given mode.
pub fn scripted_stdio_argv(mode: &str) -> Vec<String> {
    let mut argv = python3_script_argv("tests/fixtures/mcp_servers/scripted_stdio.py");
    argv.push(mode.to_string());
    argv
}

/// Argv for the scripted fixture forced to 2026-07-28 result envelopes
/// (the Auditor's internal tools/list requests carry no `_meta`, so the
/// fixture cannot detect the revision from them).
pub fn scripted_stdio_argv_v26(mode: &str) -> Vec<String> {
    let mut argv = scripted_stdio_argv(mode);
    argv.push("v26".to_string());
    argv
}

/// Argv for the scripted fixture with a pinned `initialize` result
/// `protocolVersion` — `protocol_version` is returned verbatim; the
/// special value `echo` answers the client's requested version. Both
/// exercise the Auditor's negotiated-version pin (PR-23).
pub fn scripted_stdio_argv_versioned(mode: &str, protocol_version: &str) -> Vec<String> {
    let mut argv = scripted_stdio_argv(mode);
    argv.push(format!("--protocol-version={protocol_version}"));
    argv
}

/// `GLIBC_m.n` → `(m, n)`; `None` for any other version name.
pub fn glibc_version(name: &[u8]) -> Option<(u32, u32)> {
    let rest = name.strip_prefix(b"GLIBC_")?;
    let len = rest
        .iter()
        .position(|b| !b.is_ascii_digit() && *b != b'.')
        .unwrap_or(rest.len());
    let text = std::str::from_utf8(&rest[..len]).ok()?;
    let mut parts = text.splitn(3, '.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Max `GLIBC_*` version named by an ELF's `.gnu.version_r` aux
/// records. Any structural inconsistency reads as `None` — a file this
/// walk cannot model asserts no requirement.
pub fn elf_verneed_glibc(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 64 || b[..4] != *b"\x7fELF" {
        return None;
    }
    let is64 = match b[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let le = match b[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    let get = |o: usize, n: usize| b.get(o..o.checked_add(n)?);
    let u16_at = |o: usize| -> Option<u16> {
        let s: [u8; 2] = get(o, 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(s)
        } else {
            u16::from_be_bytes(s)
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let s: [u8; 4] = get(o, 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(s)
        } else {
            u32::from_be_bytes(s)
        })
    };
    // ELF word-sized fields are u64 under ELFCLASS64, u32 under
    // ELFCLASS32.
    let xword_at = |o: usize| -> Option<u64> {
        if is64 {
            let s: [u8; 8] = get(o, 8)?.try_into().ok()?;
            Some(if le {
                u64::from_le_bytes(s)
            } else {
                u64::from_be_bytes(s)
            })
        } else {
            u32_at(o).map(u64::from)
        }
    };

    // ELF header → section table. ELF64 keeps e_shoff at 0x28 and the
    // e_shentsize/e_shnum/e_shstrndx u16s at 0x3A/0x3C/0x3E; ELF32
    // moves them to 0x20 and 0x2E/0x30/0x32.
    let (hdr_shoff, hdr_entsize, hdr_num, hdr_strndx) = if is64 {
        (0x28, 0x3A, 0x3C, 0x3E)
    } else {
        (0x20, 0x2E, 0x30, 0x32)
    };
    let shoff = xword_at(hdr_shoff)? as usize;
    let shentsize = u16_at(hdr_entsize)? as usize;
    let mut shnum = u16_at(hdr_num)? as usize;
    let mut shstrndx = u16_at(hdr_strndx)? as usize;
    if shentsize == 0 {
        return None;
    }

    // Section header field offsets: sh_name/sh_type are u32 at 0/4 in
    // both classes; ELF32's narrower fields pull offset/size/link
    // earlier.
    let (f_name, f_type, f_offset, f_size, f_link) = if is64 {
        (0, 4, 24, 32, 40)
    } else {
        (0, 4, 16, 20, 24)
    };
    let shdr = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
    let sh_u32 = |i: usize, f: usize| u32_at(shdr(i)?.checked_add(f)?);
    let sh_xword = |i: usize, f: usize| xword_at(shdr(i)?.checked_add(f)?);

    // Extended section numbering parks the real counts in section 0.
    if shnum == 0 {
        shnum = sh_xword(0, f_size)? as usize;
    }
    if shstrndx == 0xffff {
        shstrndx = sh_u32(0, f_link)? as usize;
    }
    if shstrndx >= shnum {
        return None;
    }
    let shstrtab = get(
        sh_xword(shstrndx, f_offset)? as usize,
        sh_xword(shstrndx, f_size)? as usize,
    )?;
    // A NUL-terminated string inside a string-table section.
    fn cstr(tab: &[u8], off: usize) -> Option<&[u8]> {
        let s = tab.get(off..)?;
        Some(&s[..s.iter().position(|c| *c == 0).unwrap_or(s.len())])
    }

    // SHT_GNU_verneed (0x6ffffffe): its sh_link names the string table
    // the aux vna_name offsets index (normally .dynstr).
    let mut verneed = None;
    for i in 0..shnum {
        let is_verneed = sh_u32(i, f_type) == Some(0x6fff_fffe)
            && cstr(shstrtab, sh_u32(i, f_name)? as usize) == Some(b".gnu.version_r".as_slice());
        if is_verneed {
            verneed = Some((
                sh_xword(i, f_offset)? as usize,
                sh_xword(i, f_size)? as usize,
                sh_u32(i, f_link)? as usize,
            ));
        }
    }
    let (vn_off, vn_size, linked) = verneed?;
    let dynstr = get(
        sh_xword(linked, f_offset)? as usize,
        sh_xword(linked, f_size)? as usize,
    )?;

    // Elf*_Verneed: vn_cnt u16@2, vn_aux u32@8, vn_next u32@12;
    // Elf*_Vernaux: vna_name u32@8, vna_next u32@12 — link offsets are
    // relative to the record's own start, 0 ends each chain.
    let vn_end = vn_off.checked_add(vn_size)?;
    let mut max: Option<(u32, u32)> = None;
    let mut rec = vn_off;
    let mut steps = 0usize;
    while rec.checked_add(16).is_some_and(|e| e <= vn_end) && steps <= vn_size {
        steps += 16;
        let mut aux = rec.checked_add(u32_at(rec + 8)? as usize)?;
        for _ in 0..u16_at(rec + 2)? {
            if aux.checked_add(16).is_none_or(|e| e > vn_end) {
                break;
            }
            if let Some(v) = cstr(dynstr, u32_at(aux + 8)? as usize).and_then(glibc_version)
                && max.is_none_or(|m| v > m)
            {
                max = Some(v);
            }
            match u32_at(aux + 12)? {
                0 => break,
                next => aux = aux.checked_add(next as usize)?,
            }
        }
        match u32_at(rec + 12)? {
            0 => break,
            next => rec = rec.checked_add(next as usize)?,
        }
    }
    max
}
