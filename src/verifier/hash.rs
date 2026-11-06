use std::fmt::{self, Write as _};
use std::io::{self, Read, Seek};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::audit_log::AuditLogger;
use crate::policy::{HashEntry, HashType};

mod pin;

#[cfg(unix)]
pub use pin::FdExecPlan;
/// The payload-path normalization `warden::select` mirrors for its
/// masked-tree screen (PR-05) — the same spelling the pin's
/// `PinnedEntry.path` records. `select` is Linux-only, so the
/// re-export is gated to it: any wider Unix scope would be an unused
/// import there.
#[cfg(target_os = "linux")]
pub(crate) use pin::simplify_verbatim;
pub use pin::{
    SpawnPin, VerifiedWorkload, bind_launched_workload, reverify_immediately_before_spawn,
};

const BUFFER_SIZE: usize = 8192;

/// Hash an already-open file from its start — the digest covers the
/// object the handle names, not whatever the pathname resolves to next.
fn hash_open_file(file: &mut std::fs::File) -> io::Result<String> {
    file.seek(io::SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format_sha256(hasher.finalize()))
}

/// Classification of hash targets by server type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashTarget {
    /// Native ELF/Mach-O binary
    Binary,
    /// Lock file (package-lock.json, requirements.txt, poetry.lock)
    Lockfile,
    /// Entry point script (index.js, main.py)
    Entrypoint,
    /// Docker image manifest digest
    DockerManifest,
}

impl HashTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Lockfile => "lockfile",
            Self::Entrypoint => "entrypoint",
            Self::DockerManifest => "docker-manifest",
        }
    }
}

impl fmt::Display for HashTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compute SHA-256 hash of a file using 8KB streaming chunks.
/// Returns the hash in `sha256:<hex>` format.
pub fn hash_file(path: &Path) -> io::Result<String> {
    hash_open_file(&mut std::fs::File::open(path)?)
}

/// `sha256:<hex>` of an already-materialized buffer — binds a pin to the
/// bytes analysis actually consumed, so a workload swapped between
/// inspection and hashing can never pin content the analysis never saw.
pub(crate) fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format_sha256(hasher.finalize())
}

/// Format digest bytes as `sha256:<lowercase hex>`.
/// sha2 0.11's `Output<Sha256>` no longer implements `LowerHex`.
pub(crate) fn format_sha256(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(7 + bytes.len() * 2);
    out.push_str("sha256:");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Verify a file's SHA-256 hash against an expected value.
/// Returns `Ok(true)` if hashes match, `Ok(false)` if they don't.
pub fn verify_hash(path: &Path, expected: &str) -> io::Result<bool> {
    let actual = hash_file(path)?;
    Ok(actual == expected)
}

/// Result of verifying hash entries for a server.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// All hash entries verified successfully.
    Verified,
    /// No hash entries found for this server (warn and allow).
    NoEntries,
}

/// Error when hash verification fails — the server should be blocked.
#[derive(Debug)]
pub enum VerifyError {
    /// Hash mismatch: the file exists but the hash differs from the policy.
    Mismatch {
        hash_type: HashType,
        target: String,
        expected: String,
        actual: String,
    },
    /// Target file could not be read.
    FileError {
        hash_type: HashType,
        target: String,
        error: io::Error,
    },
    /// The launched executable is not one of the verified hash targets.
    UnboundWorkload { executable: String, reason: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch {
                hash_type,
                target,
                expected,
                actual,
            } => write!(
                f,
                "{} mismatch for '{}': expected {}, got {}",
                hash_type.as_str(),
                target,
                expected,
                actual
            ),
            Self::FileError {
                hash_type,
                target,
                error,
            } => write!(
                f,
                "{} target '{}' unreadable: {}",
                hash_type.as_str(),
                target,
                error
            ),
            Self::UnboundWorkload { executable, reason } => {
                write!(
                    f,
                    "launched executable '{executable}' is not bound to a verified hash target: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify all hash entries for a given server against their target files.
///
/// - If no entries exist for the server: logs a warning and returns `Ok(NoEntries)`.
/// - If all entries match: emits `HashVerified` audit events and returns `Ok(Verified)`.
/// - On first mismatch or file error: emits `HashMismatch` audit event and returns `Err`.
///
/// Each target is hashed exactly once; for binary/entrypoint entries
/// the read runs through a pinned handle whose stamp is proved across
/// the read (`VerifiedWorkload`'s mint), so the same check the launch
/// pipeline stands behind applies here without holding the pins.
pub fn verify_server_hashes(
    server_name: &str,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
) -> Result<VerifyResult, VerifyError> {
    pin::VerifiedWorkload::new().verify_server_hashes(server_name, hash_entries, audit_logger)
}

#[cfg(test)]
mod tests;
