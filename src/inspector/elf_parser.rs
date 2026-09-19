use crate::error::InspectorError;

/// A single imported symbol with its risk classification.
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    pub name: String,
    pub library: Option<String>,
    pub category: RiskCategory,
}

/// Risk categories for imported symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskCategory {
    Network,
    FileSystem,
    Process,
    Crypto,
    Memory,
    Safe,
}

/// Aggregated risk flags derived from symbol analysis.
#[derive(Debug, Clone, Default)]
pub struct RiskFlags {
    pub network: bool,
    pub file_system: bool,
    pub process: bool,
    pub crypto: bool,
    pub memory: bool,
}

/// The result of analyzing an ELF binary's dynamic symbols.
#[derive(Debug, Clone)]
pub struct SymbolProfile {
    pub libraries: Vec<String>,
    pub imports: Vec<ImportSymbol>,
    pub risk_flags: RiskFlags,
    pub is_stripped: bool,
}

impl SymbolProfile {
    /// Empty profile for inputs whose symbols were never read (malformed
    /// slices, unsupported formats). Must be paired with a non-`Analyzed`
    /// symbol state so the empty lists are not mistaken for findings.
    pub(crate) fn empty() -> Self {
        Self {
            libraries: vec![],
            imports: vec![],
            risk_flags: RiskFlags::default(),
            is_stripped: false,
        }
    }
}

/// Classify a symbol name into a risk category.
///
/// Also used by the Mach-O parser: symbol names classify identically on
/// both platforms once the Mach-O `_` prefix is stripped.
pub(crate) fn classify_symbol(name: &str) -> RiskCategory {
    // Network-related symbols
    const NETWORK_SYMBOLS: &[&str] = &[
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "send",
        "sendto",
        "sendmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname2",
        "setsockopt",
        "getsockopt",
        "shutdown",
        "inet_pton",
        "inet_ntop",
        "inet_addr",
        "select",
        "poll",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
    ];

    // File system-related symbols
    const FS_SYMBOLS: &[&str] = &[
        "open",
        "openat",
        "creat",
        "close",
        "read",
        "write",
        "pread",
        "pwrite",
        "readv",
        "writev",
        "lseek",
        "ftruncate",
        "truncate",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "mkdirat",
        "rmdir",
        "stat",
        "fstat",
        "lstat",
        "fstatat",
        "chmod",
        "fchmod",
        "chown",
        "fchown",
        "symlink",
        "readlink",
        "link",
        "linkat",
        "opendir",
        "readdir",
        "closedir",
        "access",
        "faccessat",
        "mmap",
        "munmap",
    ];

    // Process-related symbols (high risk)
    const PROCESS_SYMBOLS: &[&str] = &[
        "execve",
        "execvp",
        "execl",
        "execlp",
        "execvpe",
        "fork",
        "vfork",
        "clone",
        "clone3",
        "system",
        "popen",
        "pclose",
        "posix_spawn",
        "posix_spawnp",
        "kill",
        "raise",
        "abort",
        "ptrace",
        "prctl",
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
        "chroot",
        "pivot_root",
        "mount",
        "umount",
        "umount2",
        "unshare",
    ];

    // Crypto-related symbols
    const CRYPTO_PREFIXES: &[&str] = &[
        "SSL_", "TLS_", "EVP_", "RAND_", "RSA_", "EC_", "AES_", "DES_", "SHA1", "SHA256", "SHA512",
        "MD5", "HMAC_", "PKCS", "X509_", "BIO_", "PEM_", "OPENSSL_", "CRYPTO_",
    ];

    // Memory-related symbols (potential exploitation)
    const MEMORY_SYMBOLS: &[&str] = &["dlopen", "dlsym", "dlclose", "mprotect", "madvise"];

    if NETWORK_SYMBOLS.contains(&name) {
        return RiskCategory::Network;
    }

    if FS_SYMBOLS.contains(&name) {
        return RiskCategory::FileSystem;
    }

    if PROCESS_SYMBOLS.contains(&name) {
        return RiskCategory::Process;
    }

    if MEMORY_SYMBOLS.contains(&name) {
        return RiskCategory::Memory;
    }

    for prefix in CRYPTO_PREFIXES {
        if name.starts_with(prefix) {
            return RiskCategory::Crypto;
        }
    }

    RiskCategory::Safe
}

/// Build aggregated risk flags from a list of import symbols.
pub(crate) fn build_risk_flags(imports: &[ImportSymbol]) -> RiskFlags {
    let mut flags = RiskFlags::default();
    for sym in imports {
        match sym.category {
            RiskCategory::Network => flags.network = true,
            RiskCategory::FileSystem => flags.file_system = true,
            RiskCategory::Process => flags.process = true,
            RiskCategory::Crypto => flags.crypto = true,
            RiskCategory::Memory => flags.memory = true,
            RiskCategory::Safe => {}
        }
    }
    flags
}

/// Parse an ELF binary from raw bytes and produce a SymbolProfile.
///
/// This handles:
/// - Dynamic library extraction (.dynamic section)
/// - Import symbol extraction (.dynsym section)
/// - Risk classification of each symbol
/// - Stripped binary detection (graceful degradation)
pub fn parse_elf(data: &[u8]) -> Result<SymbolProfile, InspectorError> {
    let elf =
        goblin::elf::Elf::parse(data).map_err(|e| InspectorError::ParseError(format!("{e}")))?;

    // Extract dynamic libraries
    let libraries: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

    // Extract import symbols from .dynsym
    let mut imports = Vec::new();
    for sym in &elf.dynsyms {
        // Skip non-import symbols:
        // - Undefined symbols (st_shndx == SHN_UNDEF) with a name are imports
        // - Skip symbols with empty names
        if sym.st_shndx != 0 {
            continue;
        }
        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };

        let category = classify_symbol(name);
        let lib = find_library_for_symbol(name, &libraries);

        imports.push(ImportSymbol {
            name: name.to_string(),
            library: lib,
            category,
        });
    }

    // Detect stripped binary: no .symtab section means stripped
    let is_stripped = elf.syms.is_empty();

    let risk_flags = build_risk_flags(&imports);

    Ok(SymbolProfile {
        libraries,
        imports,
        risk_flags,
        is_stripped,
    })
}

/// Parse a binary file, detecting format. Currently supports ELF only.
/// For non-ELF files, returns an UnsupportedFormat error.
pub fn parse_binary(data: &[u8]) -> Result<SymbolProfile, InspectorError> {
    // Check ELF magic: 0x7f 'E' 'L' 'F'
    if data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F'] {
        return parse_elf(data);
    }

    // Check for other formats to give informative errors
    if data.len() >= 4 && data[0..4] == [0xCF, 0xFA, 0xED, 0xFE] {
        return Err(InspectorError::UnsupportedFormat(
            "Mach-O 64-bit binary detected; only ELF is supported".to_string(),
        ));
    }
    if data.len() >= 4 && data[0..4] == [0xFE, 0xED, 0xFA, 0xCF] {
        return Err(InspectorError::UnsupportedFormat(
            "Mach-O 64-bit (big-endian) binary detected; only ELF is supported".to_string(),
        ));
    }
    if data.len() >= 2 && data[0..2] == *b"MZ" {
        return Err(InspectorError::UnsupportedFormat(
            "PE/COFF binary detected; only ELF is supported".to_string(),
        ));
    }

    Err(InspectorError::UnsupportedFormat(
        "unrecognized binary format".to_string(),
    ))
}

/// Heuristic: try to associate a symbol with a library based on common patterns.
fn find_library_for_symbol(name: &str, libraries: &[String]) -> Option<String> {
    // Crypto symbols -> libssl/libcrypto
    if name.starts_with("SSL_") || name.starts_with("TLS_") {
        for lib in libraries {
            if lib.contains("libssl") {
                return Some(lib.clone());
            }
        }
    }
    if name.starts_with("EVP_")
        || name.starts_with("RAND_")
        || name.starts_with("RSA_")
        || name.starts_with("OPENSSL_")
        || name.starts_with("CRYPTO_")
    {
        for lib in libraries {
            if lib.contains("libcrypto") {
                return Some(lib.clone());
            }
        }
    }

    // pthread symbols -> libpthread
    if name.starts_with("pthread_") {
        for lib in libraries {
            if lib.contains("libpthread") {
                return Some(lib.clone());
            }
        }
    }

    // dlopen/dlsym -> libdl
    if name == "dlopen" || name == "dlsym" || name == "dlclose" {
        for lib in libraries {
            if lib.contains("libdl") {
                return Some(lib.clone());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a minimal valid ELF64 binary in memory.
    // This creates the smallest possible valid ELF with no sections/symbols.
    fn minimal_elf64() -> Vec<u8> {
        let mut buf = Vec::new();

        // ELF magic
        buf.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        // EI_CLASS: ELFCLASS64
        buf.push(2);
        // EI_DATA: ELFDATA2LSB
        buf.push(1);
        // EI_VERSION: EV_CURRENT
        buf.push(1);
        // EI_OSABI: ELFOSABI_NONE
        buf.push(0);
        // EI_ABIVERSION + padding (8 bytes)
        buf.extend_from_slice(&[0u8; 8]);

        // e_type: ET_EXEC (2)
        buf.extend_from_slice(&2u16.to_le_bytes());
        // e_machine: EM_X86_64 (62)
        buf.extend_from_slice(&62u16.to_le_bytes());
        // e_version: EV_CURRENT (1)
        buf.extend_from_slice(&1u32.to_le_bytes());
        // e_entry: 0
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_phoff: 0 (no program headers)
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_shoff: 0 (no section headers)
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_flags: 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // e_ehsize: 64
        buf.extend_from_slice(&64u16.to_le_bytes());
        // e_phentsize: 56
        buf.extend_from_slice(&56u16.to_le_bytes());
        // e_phnum: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shentsize: 64
        buf.extend_from_slice(&64u16.to_le_bytes());
        // e_shnum: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shstrndx: 0
        buf.extend_from_slice(&0u16.to_le_bytes());

        buf
    }

    #[test]
    fn test_parse_minimal_elf() {
        let data = minimal_elf64();
        let profile = parse_elf(&data).expect("should parse minimal ELF");
        assert!(profile.libraries.is_empty());
        assert!(profile.imports.is_empty());
        assert!(profile.is_stripped);
        assert!(!profile.risk_flags.network);
        assert!(!profile.risk_flags.file_system);
        assert!(!profile.risk_flags.process);
        assert!(!profile.risk_flags.crypto);
    }

    #[test]
    fn test_parse_binary_detects_elf() {
        let data = minimal_elf64();
        let profile = parse_binary(&data).expect("should detect ELF");
        assert!(profile.libraries.is_empty());
    }

    #[test]
    fn test_parse_binary_rejects_pe() {
        let data = b"MZ\x90\x00rest_of_pe_header";
        let err = parse_binary(data).unwrap_err();
        match err {
            InspectorError::UnsupportedFormat(msg) => {
                assert!(msg.contains("PE/COFF"));
            }
            _ => panic!("expected UnsupportedFormat, got {err:?}"),
        }
    }

    #[test]
    fn test_parse_binary_rejects_macho() {
        // Mach-O 64-bit little-endian magic
        let data = [0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x00];
        let err = parse_binary(&data).unwrap_err();
        match err {
            InspectorError::UnsupportedFormat(msg) => {
                assert!(msg.contains("Mach-O"));
            }
            _ => panic!("expected UnsupportedFormat, got {err:?}"),
        }
    }

    #[test]
    fn test_parse_binary_rejects_unknown() {
        let data = b"NOTABINARY";
        let err = parse_binary(data).unwrap_err();
        match err {
            InspectorError::UnsupportedFormat(msg) => {
                assert!(msg.contains("unrecognized"));
            }
            _ => panic!("expected UnsupportedFormat, got {err:?}"),
        }
    }

    #[test]
    fn test_classify_network_symbols() {
        assert_eq!(classify_symbol("socket"), RiskCategory::Network);
        assert_eq!(classify_symbol("connect"), RiskCategory::Network);
        assert_eq!(classify_symbol("bind"), RiskCategory::Network);
        assert_eq!(classify_symbol("listen"), RiskCategory::Network);
        assert_eq!(classify_symbol("send"), RiskCategory::Network);
        assert_eq!(classify_symbol("recv"), RiskCategory::Network);
        assert_eq!(classify_symbol("getaddrinfo"), RiskCategory::Network);
    }

    #[test]
    fn test_classify_filesystem_symbols() {
        assert_eq!(classify_symbol("open"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("read"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("write"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("unlink"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("rename"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("mkdir"), RiskCategory::FileSystem);
        assert_eq!(classify_symbol("chmod"), RiskCategory::FileSystem);
    }

    #[test]
    fn test_classify_process_symbols() {
        assert_eq!(classify_symbol("execve"), RiskCategory::Process);
        assert_eq!(classify_symbol("fork"), RiskCategory::Process);
        assert_eq!(classify_symbol("clone"), RiskCategory::Process);
        assert_eq!(classify_symbol("system"), RiskCategory::Process);
        assert_eq!(classify_symbol("popen"), RiskCategory::Process);
        assert_eq!(classify_symbol("ptrace"), RiskCategory::Process);
        assert_eq!(classify_symbol("mount"), RiskCategory::Process);
    }

    #[test]
    fn test_classify_crypto_symbols() {
        assert_eq!(classify_symbol("SSL_connect"), RiskCategory::Crypto);
        assert_eq!(classify_symbol("EVP_EncryptInit"), RiskCategory::Crypto);
        assert_eq!(classify_symbol("RAND_bytes"), RiskCategory::Crypto);
        assert_eq!(classify_symbol("RSA_sign"), RiskCategory::Crypto);
        assert_eq!(classify_symbol("OPENSSL_init"), RiskCategory::Crypto);
    }

    #[test]
    fn test_classify_memory_symbols() {
        assert_eq!(classify_symbol("dlopen"), RiskCategory::Memory);
        assert_eq!(classify_symbol("dlsym"), RiskCategory::Memory);
        assert_eq!(classify_symbol("mprotect"), RiskCategory::Memory);
    }

    #[test]
    fn test_classify_safe_symbols() {
        assert_eq!(classify_symbol("printf"), RiskCategory::Safe);
        assert_eq!(classify_symbol("strlen"), RiskCategory::Safe);
        assert_eq!(classify_symbol("memcpy"), RiskCategory::Safe);
        assert_eq!(classify_symbol("__libc_start_main"), RiskCategory::Safe);
    }

    #[test]
    fn test_build_risk_flags() {
        let imports = vec![
            ImportSymbol {
                name: "socket".to_string(),
                library: None,
                category: RiskCategory::Network,
            },
            ImportSymbol {
                name: "open".to_string(),
                library: None,
                category: RiskCategory::FileSystem,
            },
            ImportSymbol {
                name: "printf".to_string(),
                library: None,
                category: RiskCategory::Safe,
            },
        ];
        let flags = build_risk_flags(&imports);
        assert!(flags.network);
        assert!(flags.file_system);
        assert!(!flags.process);
        assert!(!flags.crypto);
        assert!(!flags.memory);
    }

    #[test]
    fn test_build_risk_flags_empty() {
        let imports: Vec<ImportSymbol> = vec![];
        let flags = build_risk_flags(&imports);
        assert!(!flags.network);
        assert!(!flags.file_system);
        assert!(!flags.process);
        assert!(!flags.crypto);
        assert!(!flags.memory);
    }

    #[test]
    fn test_find_library_for_symbol_crypto() {
        let libs = vec![
            "libssl.so.3".to_string(),
            "libcrypto.so.3".to_string(),
            "libc.so.6".to_string(),
        ];
        assert_eq!(
            find_library_for_symbol("SSL_connect", &libs),
            Some("libssl.so.3".to_string())
        );
        assert_eq!(
            find_library_for_symbol("EVP_EncryptInit", &libs),
            Some("libcrypto.so.3".to_string())
        );
    }

    #[test]
    fn test_find_library_for_symbol_no_match() {
        let libs = vec!["libc.so.6".to_string()];
        assert_eq!(find_library_for_symbol("printf", &libs), None);
    }

    #[test]
    fn test_stripped_binary_detection() {
        let data = minimal_elf64();
        let profile = parse_elf(&data).expect("should parse");
        // Our minimal ELF has no .symtab, so it's "stripped"
        assert!(profile.is_stripped);
    }

    #[test]
    fn test_parse_elf_invalid_data() {
        let data = b"not an elf file at all";
        let result = parse_elf(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            InspectorError::ParseError(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_elf_truncated() {
        // Just the ELF magic, truncated
        let data = &[0x7f, b'E', b'L', b'F'];
        let result = parse_elf(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_binary_empty() {
        let data: &[u8] = &[];
        let result = parse_binary(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            InspectorError::UnsupportedFormat(msg) => {
                assert!(msg.contains("unrecognized"));
            }
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn test_symbol_profile_fields() {
        let profile = SymbolProfile {
            libraries: vec!["libc.so.6".to_string()],
            imports: vec![ImportSymbol {
                name: "execve".to_string(),
                library: Some("libc.so.6".to_string()),
                category: RiskCategory::Process,
            }],
            risk_flags: RiskFlags {
                process: true,
                ..Default::default()
            },
            is_stripped: false,
        };
        assert_eq!(profile.libraries.len(), 1);
        assert_eq!(profile.imports.len(), 1);
        assert_eq!(profile.imports[0].name, "execve");
        assert_eq!(profile.imports[0].category, RiskCategory::Process);
        assert!(profile.risk_flags.process);
        assert!(!profile.is_stripped);
    }
}
