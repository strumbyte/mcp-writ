//! Mach-O slice parsing for the Inspector (P6).
//!
//! Responsibilities:
//! - extract one thin/fat slice's bytes (slice-relative offsets stay
//!   distinct from file-absolute offsets — [`super::target::CodeRegion`]);
//! - discover executable code regions (`__TEXT,__text` and other
//!   instruction-carrying sections);
//! - extract libraries/imports/symbols via `goblin::mach`;
//! - extract and classify strings from data-bearing sections;
//! - read the target platform from `LC_BUILD_VERSION`/`LC_VERSION_MIN_*`.
//!
//! Scope limits (kept visible in analysis state):
//! - only the first plain `arm64` slice of a fat container is analyzed;
//!   arm64e, arm64_32 and non-arm64 slices record an `Unsupported` state;
//! - indirect calls, dynamic loading and code inside shared libraries are
//!   not tracked — the slice's own bytes are all we decode.

use goblin::mach::MachO;
use goblin::mach::constants::{self, cputype};
use goblin::mach::load_command::{self as lc, CommandVariant};

use crate::error::InspectorError;
use crate::inspector::elf_parser::{
    ImportSymbol, SymbolProfile, build_risk_flags, classify_symbol,
};
use crate::inspector::strings::{self, StringFindings};
use crate::inspector::target::MachOPlatform;

/// One executable Mach-O section discovered in a slice.
pub(crate) struct MachOCodeRegion<'a> {
    /// `"SEGNAME,SECTNAME"` — e.g. `__TEXT,__text`.
    pub name: String,
    /// File offset relative to the start of the slice.
    pub slice_offset: u64,
    /// Virtual address (`section.addr`).
    pub vaddr: u64,
    /// Section bytes (already bounds-checked against the slice).
    pub bytes: &'a [u8],
}

/// Section names treated as string-bearing, mirroring the ELF path's
/// `.rodata`/`.data` coverage.
const STRING_SECTIONS: &[&str] = &[
    "__cstring",
    "__const",
    "__data",
    "__ustring",
    "__objc_methname",
    "__info_plist",
];

/// Parse one Mach-O slice (thin file bytes or an extracted fat slice).
///
/// A fat slice is a self-contained Mach-O: its load-command file offsets
/// are relative to the slice start, which is why callers pass the slice
/// bytes with offset 0 — never conflated with container offsets.
pub(crate) fn parse_slice(slice_bytes: &[u8]) -> Result<MachO<'_>, InspectorError> {
    MachO::parse(slice_bytes, 0).map_err(|e| InspectorError::ParseError(format!("{e}")))
}

/// Derived-state bounds for executable-region enumeration, mirroring
/// the ELF path's `MAX_CODE_REGIONS`. The input cap covers file bytes,
/// not the decode work a hostile section table multiplies: every
/// declared executable region is independently disassembled downstream,
/// so the retained set is capped in count and in aggregate bytes.
pub(crate) const MAX_CODE_REGIONS: usize = 4096;
/// Aggregate decode budget for one slice — the same bound the top-level
/// read applies to the input. Coalescing below already keeps retained
/// ranges disjoint, so their sum can never exceed the slice; the
/// constant makes that invariant an explicit budget rather than an
/// emergent property.
pub(crate) const MAX_CODE_REGION_BYTES: u64 = crate::inspector::MAX_ANALYZED_FILE_BYTES;
/// Executable-section *declarations* retained for coalescing — larger
/// than `MAX_CODE_REGIONS` so overlapping declarations cannot crowd
/// later disjoint sections out of the kept set, but still bounded:
/// every candidate costs a name `String` and a sort slot *before* the
/// kept caps below apply, and a hostile table (~80 B per `section_64`
/// load command inside a 512 MiB input) could otherwise stack millions
/// of allocations on top of the input bound.
const MAX_SECTION_CANDIDATES: usize = MAX_CODE_REGIONS * 4;
/// Cumulative bytes `string_findings` rescans in one slice — the input
/// bound again: disjoint declared ranges already sum to less than the
/// slice, so the bound only bites when declarations overlap.
const MAX_STRING_SCAN_BYTES: u64 = crate::inspector::MAX_ANALYZED_FILE_BYTES;

/// Executable sections of a parsed Mach-O, sorted by file offset.
///
/// A section counts as code when it carries an instruction attribute
/// (`S_ATTR_PURE_INSTRUCTIONS`/`S_ATTR_SOME_INSTRUCTIONS` — set by the
/// toolchain on `__text`, `__stubs`, `__stub_helper`, …) or is named
/// `__text` inside an execute-protected segment. Every returned region is
/// decoded by the caller; coverage gaps surface as `Partial`, never as a
/// silent clean scan.
///
/// Overlapping declarations are coalesced before return: a crafted
/// table can point thousands of executable sections at the same file
/// bytes, and decoding each independently would multiply work far past
/// the input bound. A section whose range starts inside an
/// earlier-kept one is dropped whole rather than clipped — clipping
/// could start the decode mid-instruction and fabricate sites. Dropped
/// or budget-cut sections return as a `Some` detail note so the caller
/// can mark the analysis `Partial`; the region list never silently
/// narrows.
pub(crate) fn executable_sections<'a>(
    macho: &'a MachO<'a>,
    slice_len: u64,
) -> Result<(Vec<MachOCodeRegion<'a>>, Option<String>), InspectorError> {
    let mut regions = Vec::new();
    let mut candidates_truncated = false;
    'outer: for segment in &macho.segments {
        let seg_exec = segment.initprot & constants::VM_PROT_EXECUTE != 0;
        // Iterating `&Segment` reads each `section_64` on demand;
        // `segment.sections()` would collect every declaration into a
        // Vec *before* `MAX_SECTION_CANDIDATES` below could apply — a
        // single segment with a huge `nsects` would re-open the
        // allocation path this bound exists to close.
        for section in segment.into_iter() {
            let (sect, data) =
                section.map_err(|e| InspectorError::ParseError(format!("sections: {e}")))?;
            let sectname = sect.name().unwrap_or("");
            let has_instr_attrs = sect.flags
                & (constants::S_ATTR_PURE_INSTRUCTIONS | constants::S_ATTR_SOME_INSTRUCTIONS)
                != 0;
            if !(has_instr_attrs || (seg_exec && sectname == "__text")) {
                continue;
            }
            // The declared section range must fit inside the slice. The
            // fields are untrusted u64/u32 — a size near u64::MAX must be a
            // parse error, not a wrapped `end` that passes the check.
            let end = (sect.offset as u64).checked_add(sect.size);
            if end.is_none_or(|e| e > slice_len) || data.len() as u64 != sect.size {
                return Err(InspectorError::ParseError(format!(
                    "section {},{} range 0x{:x}..{} outside slice (len 0x{:x})",
                    sect.segname().unwrap_or("?"),
                    sectname,
                    sect.offset,
                    end.map_or_else(|| "overflow".to_string(), |e| format!("0x{e:x}")),
                    slice_len,
                )));
            }
            // Bound the candidate pool *before* the name alloc and the
            // sort — declarations past this point are coverage the
            // analysis reports as cut, not work it still performs.
            if regions.len() >= MAX_SECTION_CANDIDATES {
                candidates_truncated = true;
                break 'outer;
            }
            regions.push(MachOCodeRegion {
                name: format!("{},{}", sect.segname().unwrap_or(""), sectname),
                slice_offset: sect.offset as u64,
                vaddr: sect.addr,
                bytes: data,
            });
        }
    }
    // Decode must follow the file, not load-command order — coverage is
    // tracked against sorted file ranges below.
    regions.sort_by_key(|r| r.slice_offset);
    let mut kept: Vec<MachOCodeRegion> = Vec::new();
    let mut covered_end = 0u64;
    let mut kept_bytes = 0u64;
    let mut coalesced = 0usize;
    let mut truncated = false;
    for r in regions {
        if r.slice_offset < covered_end {
            coalesced += 1;
            continue;
        }
        if kept.len() >= MAX_CODE_REGIONS
            || kept_bytes + r.bytes.len() as u64 > MAX_CODE_REGION_BYTES
        {
            truncated = true;
            break;
        }
        covered_end = r.slice_offset + r.bytes.len() as u64;
        kept_bytes += r.bytes.len() as u64;
        kept.push(r);
    }
    let partial = if coalesced == 0 && !truncated && !candidates_truncated {
        None
    } else {
        let mut note = String::new();
        if coalesced > 0 {
            note.push_str(&format!(
                "{coalesced} executable section(s) overlapping an earlier range \
                 were coalesced out"
            ));
        }
        if truncated {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str("executable region bound reached");
        }
        if candidates_truncated {
            if !note.is_empty() {
                note.push_str("; ");
            }
            note.push_str("executable section declarations truncated");
        }
        note.push_str("; syscall findings are a lower bound");
        Some(note)
    };
    Ok((kept, partial))
}

/// Mach-O symbols/imports for the capability profile.
///
/// `imports()` resolves the bind opcodes (`LC_DYLD_INFO*` / chained
/// fixups); when bind info is absent or fails to decode, undefined
/// external symbols in `LC_SYMTAB` are listed as imports instead so the
/// findings stay non-empty rather than silently empty. The returned detail
/// string flags a partial import view (`Partial` state upstream).
///
/// Derived-metadata budgets: the input cap bounds file bytes, not the
/// count or size of the owned collections a hostile load-command layout
/// makes us retain. Every collection below is capped; overflow sets
/// `partial` rather than silently dropping evidence.
pub(crate) const MAX_IMPORTED_LIBS: usize = 4096;
pub(crate) const MAX_IMPORTS: usize = 65_536;
pub(crate) const MAX_IMPORT_NAME_BYTES: usize = 8 * 1024 * 1024;
/// Symbol-table entries we scan before declaring the table too large.
const MAX_SYMTAB_SCAN: usize = 4 * 1024 * 1024;

fn merge_partial(partial: &mut Option<String>, msg: &str) {
    *partial = Some(match partial.take() {
        Some(p) => format!("{p}; {msg}"),
        None => msg.to_string(),
    });
}

/// Import `name`s keep their raw Mach-O form (leading `_` and all) for
/// display and evidence; classification strips the `_` prefix so risk
/// categories match the ELF path.
pub(crate) fn symbol_profile(macho: &MachO) -> (SymbolProfile, Option<String>) {
    let mut partial: Option<String> = None;
    let mut name_bytes = 0usize;

    let mut libraries: Vec<String> = Vec::new();
    for l in macho.libs.iter().filter(|l| **l != "self") {
        if libraries.len() >= MAX_IMPORTED_LIBS || name_bytes + l.len() > MAX_IMPORT_NAME_BYTES {
            merge_partial(&mut partial, "library list truncated");
            break;
        }
        name_bytes += l.len();
        libraries.push(l.to_string());
    }

    let mut imports: Vec<ImportSymbol> = Vec::new();
    // O(1) membership for the undefined-symbol dedup — a linear scan
    // per symbol is quadratic work on a hostile LC_SYMTAB.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    match macho.imports() {
        Ok(list) => {
            for imp in list {
                if imports.len() >= MAX_IMPORTS
                    || name_bytes + imp.name.len() + imp.dylib.len() > MAX_IMPORT_NAME_BYTES
                {
                    merge_partial(&mut partial, "import list truncated");
                    break;
                }
                name_bytes += imp.name.len() + imp.dylib.len();
                seen.insert(imp.name);
                let normalized = imp.name.strip_prefix('_').unwrap_or(imp.name);
                imports.push(ImportSymbol {
                    name: imp.name.to_string(),
                    library: (imp.dylib != "self").then(|| imp.dylib.to_string()),
                    category: classify_symbol(normalized),
                });
            }
        }
        Err(e) => {
            merge_partial(&mut partial, &format!("bind/dyld info unavailable: {e}"));
        }
    }

    // Undefined external symbols in LC_SYMTAB are imports too (this is also
    // the only source for object files, which have no bind opcodes).
    let mut sym_count = 0usize;
    let mut sym_err = false;
    for sym in macho.symbols() {
        match sym {
            Ok((name, nlist)) => {
                sym_count += 1;
                if sym_count > MAX_SYMTAB_SCAN {
                    merge_partial(&mut partial, "symbol table truncated");
                    break;
                }
                if nlist.is_undefined() && nlist.is_global() && !name.is_empty() {
                    if seen.contains(name) {
                        continue;
                    }
                    if imports.len() >= MAX_IMPORTS
                        || name_bytes + name.len() > MAX_IMPORT_NAME_BYTES
                    {
                        merge_partial(&mut partial, "import list truncated");
                        break;
                    }
                    name_bytes += name.len();
                    seen.insert(name);
                    imports.push(ImportSymbol {
                        name: name.to_string(),
                        library: None,
                        category: classify_symbol(name.strip_prefix('_').unwrap_or(name)),
                    });
                }
            }
            Err(_) => sym_err = true,
        }
    }
    if sym_err {
        merge_partial(&mut partial, "symbol table partially unreadable");
    }

    let is_stripped = sym_count == 0;
    let risk_flags = build_risk_flags(&imports);
    (
        SymbolProfile {
            libraries,
            imports,
            risk_flags,
            is_stripped,
        },
        partial,
    )
}

/// Extract and classify strings from the slice's data-bearing sections.
///
/// Returns `Err` only when section iteration itself fails; out-of-range or
/// empty sections are skipped so one bad section cannot mask the rest.
pub(crate) fn string_findings(macho: &MachO) -> Result<StringFindings, InspectorError> {
    let mut raw = Vec::new();
    let mut truncated = false;
    // Bounds on the *scan*, not just the findings: every matching
    // section is rescanned in full, so a table of overlapping
    // `__cstring` declarations pointing at one large string-free region
    // would multiply work past the input bound without ever reaching
    // `MAX_RAW_STRINGS`. Exact-duplicate declarations share one
    // `(offset, size)` range and are scanned once — a rescan cannot add
    // findings, so dedup is not itself a truncation. The distinct-range
    // count and cumulative scanned bytes are both capped; either bound
    // marks the findings truncated rather than silently narrowing.
    let mut seen_ranges = std::collections::HashSet::new();
    let mut scanned_bytes = 0u64;
    'outer: for segment in &macho.segments {
        // Lazy section iteration — see `executable_sections` above; a
        // collecting `sections()` call would allocate every declared
        // section of a huge segment before the string cap could bite.
        for section in segment.into_iter() {
            let (sect, data) =
                section.map_err(|e| InspectorError::ParseError(format!("sections: {e}")))?;
            if !STRING_SECTIONS.contains(&sect.name().unwrap_or("")) || data.is_empty() {
                continue;
            }
            if !seen_ranges.insert((sect.offset as u64, sect.size)) {
                continue;
            }
            if seen_ranges.len() > MAX_SECTION_CANDIDATES
                || scanned_bytes + data.len() as u64 > MAX_STRING_SCAN_BYTES
            {
                truncated = true;
                break 'outer;
            }
            scanned_bytes += data.len() as u64;
            let (extracted, buf_truncated) = strings::extract_strings_from_bytes(data);
            truncated |= buf_truncated;
            raw.extend(extracted);
            if raw.len() >= strings::MAX_RAW_STRINGS {
                raw.truncate(strings::MAX_RAW_STRINGS);
                truncated = true;
                break 'outer;
            }
        }
    }
    Ok(strings::classify_strings(&raw, truncated))
}

/// Target platform from `LC_BUILD_VERSION` or the `LC_VERSION_MIN_*`
/// command; `Unknown` when no platform command is present.
pub(crate) fn detect_platform(macho: &MachO) -> MachOPlatform {
    use MachOPlatform as P;
    for cmd in &macho.load_commands {
        let platform = match cmd.command {
            CommandVariant::BuildVersion(bv) => Some(match bv.platform {
                lc::PLATFORM_MACOS => P::MacOs,
                lc::PLATFORM_IOS => P::Ios,
                lc::PLATFORM_TVOS => P::Tvos,
                lc::PLATFORM_WATCHOS => P::WatchOs,
                lc::PLATFORM_BRIDGEOS => P::BridgeOs,
                lc::PLATFORM_MACCATALYST => P::MacCatalyst,
                lc::PLATFORM_IOSSIMULATOR => P::IosSimulator,
                lc::PLATFORM_TVOSSIMULATOR => P::TvosSimulator,
                lc::PLATFORM_WATCHOSSIMULATOR => P::WatchosSimulator,
                lc::PLATFORM_DRIVERKIT => P::DriverKit,
                lc::PLATFORM_VISIONOS => P::VisionOs,
                lc::PLATFORM_VISIONOSSIMULATOR => P::VisionosSimulator,
                other => P::Other(other),
            }),
            CommandVariant::VersionMinMacosx(_) => Some(P::MacOs),
            CommandVariant::VersionMinIphoneos(_) => Some(P::Ios),
            CommandVariant::VersionMinTvos(_) => Some(P::Tvos),
            CommandVariant::VersionMinWatchos(_) => Some(P::WatchOs),
            _ => None,
        };
        if let Some(p) = platform {
            return p;
        }
    }
    P::Unknown
}

/// Whether the parsed slice header describes a supported analysis subject:
/// 64-bit, little-endian, `CPU_TYPE_ARM64` with a non-arm64e subtype.
/// Returns `Err(detail)` describing the unsupported variant.
pub(crate) fn supported_slice_variant(macho: &MachO) -> Result<(), String> {
    if !macho.is_64 {
        return Err("32-bit Mach-O header".to_string());
    }
    if !macho.little_endian {
        return Err("big-endian Mach-O".to_string());
    }
    let subtype = macho.header.cpusubtype & !cputype::CPU_SUBTYPE_MASK;
    if macho.header.cputype == cputype::CPU_TYPE_ARM64_32 {
        return Err("arm64_32 (ILP32) slice".to_string());
    }
    if macho.header.cputype != cputype::CPU_TYPE_ARM64 {
        return Err(format!("cputype {:#x} is not arm64", macho.header.cputype));
    }
    if subtype == cputype::CPU_SUBTYPE_ARM64_E {
        return Err("arm64e slice (pointer-authentication variant)".to_string());
    }
    Ok(())
}
