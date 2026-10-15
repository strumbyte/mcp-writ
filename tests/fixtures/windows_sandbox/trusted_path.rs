// std-only stand-in for `src/trusted_path.rs` inside the plain-rustc
// fixture crate: the shipped module resolves System32 through
// `GetSystemDirectoryW` and validates the DACL of every component —
// both need crates the rustc fixture build has no access to. The
// fixture's agent leg only spells `netsh.exe` for a best-effort guest
// firewall rule, so `%SystemRoot%\System32` plus an existence check is
// the honest equivalent here: the disposable VM populates SystemRoot
// itself and a wrong answer just skips the rule into `agent.log`.

use std::path::PathBuf;

/// `rel` is the System32-relative spelling (`"netsh.exe"`); `Some` only
/// when the resolved file exists. Same signature as the shipped
/// `trusted_path::system32_exe`.
pub(crate) fn system32_exe(rel: &str) -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot")?;
    let candidate = PathBuf::from(root).join("System32").join(rel);
    candidate.is_file().then_some(candidate)
}
