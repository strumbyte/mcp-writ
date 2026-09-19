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

/// Executable sections of a parsed Mach-O, in load-command order.
///
/// A section counts as code when it carries an instruction attribute
/// (`S_ATTR_PURE_INSTRUCTIONS`/`S_ATTR_SOME_INSTRUCTIONS` — set by the
/// toolchain on `__text`, `__stubs`, `__stub_helper`, …) or is named
/// `__text` inside an execute-protected segment. Every returned region is
/// decoded by the caller; coverage gaps surface as `Partial`, never as a
/// silent clean scan.
pub(crate) fn executable_sections<'a>(
    macho: &'a MachO<'a>,
    slice_len: u64,
) -> Result<Vec<MachOCodeRegion<'a>>, InspectorError> {
    let mut regions = Vec::new();
    for segment in &macho.segments {
        let seg_exec = segment.initprot & constants::VM_PROT_EXECUTE != 0;
        let sections = segment
            .sections()
            .map_err(|e| InspectorError::ParseError(format!("sections: {e}")))?;
        for (sect, data) in sections {
            let sectname = sect.name().unwrap_or("");
            let has_instr_attrs = sect.flags
                & (constants::S_ATTR_PURE_INSTRUCTIONS | constants::S_ATTR_SOME_INSTRUCTIONS)
                != 0;
            if !(has_instr_attrs || (seg_exec && sectname == "__text")) {
                continue;
            }
            // The declared section range must fit inside the slice.
            let end = sect.offset as u64 + sect.size;
            if end > slice_len || data.len() as u64 != sect.size {
                return Err(InspectorError::ParseError(format!(
                    "section {},{} range 0x{:x}..0x{:x} outside slice (len 0x{:x})",
                    sect.segname().unwrap_or("?"),
                    sectname,
                    sect.offset,
                    end,
                    slice_len,
                )));
            }
            regions.push(MachOCodeRegion {
                name: format!("{},{}", sect.segname().unwrap_or(""), sectname),
                slice_offset: sect.offset as u64,
                vaddr: sect.addr,
                bytes: data,
            });
        }
    }
    Ok(regions)
}

/// Mach-O symbols/imports for the capability profile.
///
/// `imports()` resolves the bind opcodes (`LC_DYLD_INFO*` / chained
/// fixups); when bind info is absent or fails to decode, undefined
/// external symbols in `LC_SYMTAB` are listed as imports instead so the
/// findings stay non-empty rather than silently empty. The returned detail
/// string flags a partial import view (`Partial` state upstream).
///
/// Import `name`s keep their raw Mach-O form (leading `_` and all) for
/// display and evidence; classification strips the `_` prefix so risk
/// categories match the ELF path.
pub(crate) fn symbol_profile(macho: &MachO) -> (SymbolProfile, Option<String>) {
    let libraries: Vec<String> = macho
        .libs
        .iter()
        .filter(|l| **l != "self")
        .map(|l| l.to_string())
        .collect();

    let mut imports: Vec<ImportSymbol> = Vec::new();
    let mut partial: Option<String> = None;
    match macho.imports() {
        Ok(list) => {
            for imp in list {
                let normalized = imp.name.strip_prefix('_').unwrap_or(imp.name);
                imports.push(ImportSymbol {
                    name: imp.name.to_string(),
                    library: (imp.dylib != "self").then(|| imp.dylib.to_string()),
                    category: classify_symbol(normalized),
                });
            }
        }
        Err(e) => {
            partial = Some(format!("bind/dyld info unavailable: {e}"));
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
                if nlist.is_undefined()
                    && nlist.is_global()
                    && !name.is_empty()
                    && !imports.iter().any(|i| i.name == name)
                {
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
        partial = Some(match partial {
            Some(p) => format!("{p}; symbol table partially unreadable"),
            None => "symbol table partially unreadable".to_string(),
        });
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
    for segment in &macho.segments {
        let sections = segment
            .sections()
            .map_err(|e| InspectorError::ParseError(format!("sections: {e}")))?;
        for (sect, data) in sections {
            if STRING_SECTIONS.contains(&sect.name().unwrap_or("")) {
                raw.extend(strings::extract_strings_from_bytes(data));
            }
        }
    }
    Ok(strings::classify_strings(&raw))
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
