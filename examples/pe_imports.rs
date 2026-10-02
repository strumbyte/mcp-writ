//! PE import inspection for the Windows guest contract.
//!
//! Usage:
//!   pe-imports <file> [--require-clean]
//!
//! Prints the PE's machine architecture and every imported DLL, then the
//! subset that names an MSVC redistributable Server Core does not ship.
//! `--require-clean` exits 1 when that subset is non-empty — the release
//! pipeline uses it to prove the shipped `crt-static` runner loads on a
//! bare Server Core image without app-local CRT staging.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: pe-imports <file> [--require-clean]");
        return ExitCode::from(2);
    };
    let require_clean = args.any(|a| a == "--require-clean");

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read '{path}': {e}");
            return ExitCode::from(2);
        }
    };

    let pe = match goblin::pe::PE::parse(&data) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("error: '{path}' is not a parseable PE: {e}");
            return ExitCode::from(2);
        }
    };

    println!("machine: {:#06x}", pe.header.coff_header.machine);
    println!("imports ({}):", pe.libraries.len());
    for lib in &pe.libraries {
        println!("  {lib}");
    }

    let redist = mcp_writ::container::pe_magic::required_redist_dlls(&data).unwrap_or_default();
    if redist.is_empty() {
        println!("redist: none");
        return ExitCode::SUCCESS;
    }
    println!("redist ({}):", redist.len());
    for dll in &redist {
        println!("  {dll}");
    }
    if require_clean {
        eprintln!("error: '{path}' imports MSVC redistributables absent from Server Core");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
