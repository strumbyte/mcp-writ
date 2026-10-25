// std-only stand-in for `src/trusted_path.rs` inside the plain-rustc
// fixture crate: the shipped module resolves System32 through
// `GetSystemDirectoryW` and validates the DACL of every component —
// both need crates the rustc fixture build has no access to. The
// fixture's agent leg only spells `netsh.exe` for a best-effort guest
// firewall rule, so `%SystemRoot%\System32` plus an existence check is
// the honest equivalent here: the disposable VM populates SystemRoot
// itself and a wrong answer just skips the rule into `agent.log`.

use std::path::PathBuf;
use std::process::Command as StdCommand;

/// Stand-in for the shipped `BoundDriver`: the validated spelling plus
/// the only API the agent consumes (`std_command` — the real one also
/// re-verifies the pinned file identity, which a std-only fixture
/// cannot do; the guest-side netsh is best-effort, so an honest
/// unverified spawn matches the stand-in contract).
pub(crate) struct BoundDriver {
    path: PathBuf,
}

impl BoundDriver {
    pub(crate) fn std_command(&self) -> std::io::Result<StdCommand> {
        Ok(StdCommand::new(&self.path))
    }
}

/// `rel` is the System32-relative spelling (`"netsh.exe"`); `Some` only
/// when the resolved file exists. Same signature as the shipped
/// `trusted_path::system32_exe` — a bound driver handle, not a bare path.
pub(crate) fn system32_exe(rel: &str) -> Option<BoundDriver> {
    let root = std::env::var_os("SystemRoot")?;
    let candidate = PathBuf::from(root).join("System32").join(rel);
    candidate.is_file().then_some(BoundDriver { path: candidate })
}
