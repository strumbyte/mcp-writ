//! The verify stage: `verify_server_hashes` mints one held pin per
//! launch-identity target — open handle, pre-hash stamp, verified
//! digest — and `VerifiedWorkload` carries them to the bind and
//! reverify stages so they never re-read the object by pathname.

use std::io;
use std::path::Path;

use uuid::Uuid;

use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
use crate::verifier::hash::{VerifyError, VerifyResult, hash_file, hash_open_file};

use super::anchor::{open_pinned, same_open_object};
use super::stamp::{OpenStamp, record_stamp, stamp_unchanged};

/// The verified launch workload — one held pin per binary/entrypoint
/// hash entry, minted as the entries verified: the kept-open object,
/// the stamp recorded before hashing, and the verified digest. Bind
/// and reverify consume these instead of re-reading the targets by
/// pathname — their freshness proof is the held object's identity plus
/// its stamp, with a content re-hash only when the object provably
/// changed (D-6). Entries that bind nothing at launch (lockfile and
/// docker-manifest hashes) are verified but held by no pin.
///
/// Pins are index-aligned with the `hash_entries` slice the workload
/// verified against — bind/reverify must be handed the same slice.
pub struct VerifiedWorkload {
    pins: Vec<(usize, HeldTarget)>,
}

/// A launch-identity target verified under a held handle — see
/// [`VerifiedWorkload`]. `digest` equals `expected` whenever the pin is
/// healthy: verify enforced it and every freshness re-check restores
/// the invariant or fails.
pub(super) struct HeldTarget {
    pub(super) hash_type: HashType,
    /// `entry.target` — the manifest spelling, reused as the error
    /// label; the pin was opened through it at verify.
    pub(super) target: String,
    /// `entry.hash_value` — the pinned digest.
    pub(super) expected: String,
    pub(super) file: std::fs::File,
    pub(super) stamp: OpenStamp,
    /// The held object's verified digest — `expected`, restated.
    pub(super) digest: String,
}

impl HeldTarget {
    /// Open `path` pinned, stamp it, hash the held object, and prove
    /// the stamp held across the read — the pinless mint: callers
    /// without a workload re-establish the same anchor a
    /// [`VerifiedWorkload`] pin carries. `expected` is the computed
    /// digest itself — a bare mint verifies no pin, only freshness.
    pub(super) fn open_fresh(
        path: &Path,
        hash_type: HashType,
        target: String,
    ) -> Result<Self, VerifyError> {
        let mut file = open_pinned(path).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        let stamp = record_stamp(&file).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        let digest = hash_open_file(&mut file).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        if !stamp_unchanged(&file, &stamp) {
            return Err(VerifyError::Mismatch {
                hash_type,
                target,
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        Ok(Self {
            hash_type,
            target,
            expected: digest.clone(),
            file,
            stamp,
            digest,
        })
    }

    /// Freshness without a read on the happy path: `path` must still
    /// name the held object and the object's stamp must hold — the
    /// verified digest stands. A retargeted `path` re-pins on the
    /// object it now names and re-hashes it — the pathname re-read
    /// judgment this check replaces, where identical bytes re-anchor
    /// the pin and anything else is a mismatch. A changed stamp falls
    /// back to a content re-hash through the held handle — the stamp
    /// only *detects*; the digest still decides (D-6).
    pub(super) fn revalidate(&mut self, path: &Path) -> Result<(), VerifyError> {
        if !same_open_object(path, &self.file) {
            let mut file = open_pinned(path).map_err(|error| self.file_error(error))?;
            let stamp = record_stamp(&file).map_err(|error| self.file_error(error))?;
            let actual = hash_open_file(&mut file).map_err(|error| self.file_error(error))?;
            // Same rule as `open_fresh`: prove the stamp held across the
            // read, so a mid-read rewrite cannot anchor the re-pinned
            // object on hybrid bytes.
            if !stamp_unchanged(&file, &stamp) {
                return Err(VerifyError::Mismatch {
                    hash_type: self.hash_type,
                    target: self.target.clone(),
                    expected: "a consistent read of the pinned object".to_string(),
                    actual: "file modified during hashing".to_string(),
                });
            }
            if actual != self.expected {
                return Err(self.mismatch(actual));
            }
            self.file = file;
            self.stamp = stamp;
            self.digest = actual;
            return Ok(());
        }
        // The stamp shortcut holds only when the recorded ctime is
        // provably older than the record window — a stamp inside the
        // filesystem's timestamp granularity cannot rule out a
        // same-tick rewrite, so it falls to the digest like any moved
        // stamp.
        if stamp_unchanged(&self.file, &self.stamp) && self.stamp.outside_timestamp_window() {
            return Ok(());
        }
        // A moved stamp re-reads through the held handle — stamp the
        // object *before* the read and prove the stamp held across it,
        // so a mid-read rewrite cannot anchor the pin on hybrid bytes.
        let pre = record_stamp(&self.file).map_err(|error| self.file_error(error))?;
        let actual = hash_open_file(&mut self.file).map_err(|error| self.file_error(error))?;
        if !stamp_unchanged(&self.file, &pre) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        if actual != self.expected {
            return Err(self.mismatch(actual));
        }
        self.stamp = pre;
        self.digest = actual;
        Ok(())
    }

    /// The strict form of [`Self::revalidate`]: `path` must still name
    /// the *held* object — a retarget is a mismatch outright rather
    /// than a re-pin, for callers where re-anchoring would silently
    /// bind a different object than the pin covered. Stamp handling is
    /// unchanged: a changed stamp re-hashes and the digest decides.
    pub(super) fn revalidate_held(&mut self, path: &Path) -> Result<(), VerifyError> {
        if !same_open_object(path, &self.file) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "the pinned object".to_string(),
                actual: "pathname now resolves to a different object".to_string(),
            });
        }
        if stamp_unchanged(&self.file, &self.stamp) && self.stamp.outside_timestamp_window() {
            return Ok(());
        }
        let pre = record_stamp(&self.file).map_err(|error| self.file_error(error))?;
        let actual = hash_open_file(&mut self.file).map_err(|error| self.file_error(error))?;
        if !stamp_unchanged(&self.file, &pre) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        if actual != self.expected {
            return Err(self.mismatch(actual));
        }
        self.stamp = pre;
        self.digest = actual;
        Ok(())
    }

    fn file_error(&self, error: io::Error) -> VerifyError {
        VerifyError::FileError {
            hash_type: self.hash_type,
            target: self.target.clone(),
            error,
        }
    }

    fn mismatch(&self, actual: String) -> VerifyError {
        VerifyError::Mismatch {
            hash_type: self.hash_type,
            target: self.target.clone(),
            expected: self.expected.clone(),
            actual,
        }
    }
}

impl Default for VerifiedWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifiedWorkload {
    /// An empty workload — [`Self::verify_server_hashes`] fills it.
    pub fn new() -> Self {
        Self { pins: Vec::new() }
    }

    /// `verify_server_hashes` over `server_name`'s entries, minting a
    /// held pin for each launch-identity target (binary and entrypoint
    /// hashes): the target opens pinned, stamps before hashing, and is
    /// hashed through the kept handle — handle, stamp, and digest all
    /// stay with the workload so later stages never re-read the object
    /// by path. Other entry types hash by path as before. The
    /// `hash.verified` / `hash.mismatch` audit events are emitted at
    /// this stage — the only place they are.
    pub fn verify_server_hashes(
        &mut self,
        server_name: &str,
        hash_entries: &[HashEntry],
        audit_logger: &AuditLogger,
    ) -> Result<VerifyResult, VerifyError> {
        let entries: Vec<(usize, &HashEntry)> = hash_entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.server_name == server_name)
            .collect();

        if entries.is_empty() {
            tracing::warn!(
                server = server_name,
                "No hash entries in policy for server; allowing startup"
            );
            return Ok(VerifyResult::NoEntries);
        }

        let correlation_id = Uuid::now_v7();

        for (i, entry) in entries {
            let target_path = Path::new(&entry.target);
            let outcome = if matches!(entry.hash_type, HashType::Binary | HashType::Entrypoint) {
                HeldTarget::mint(entry, target_path).map(|held| (held.digest.clone(), Some(held)))
            } else {
                hash_file(target_path)
                    .map(|digest| (digest, None))
                    .map_err(|error| VerifyError::FileError {
                        hash_type: entry.hash_type,
                        target: entry.target.clone(),
                        error,
                    })
            };

            let (actual_hash, held) = match outcome {
                Ok(pair) => pair,
                Err(source) => {
                    let mut evt = AuditEvent::new(
                        correlation_id,
                        EventType::HashMismatch,
                        Severity::Critical,
                        Outcome::Failure,
                        Action::Denied,
                    );
                    evt.target_server = Some(server_name.to_string());
                    evt.details = Some(match &source {
                        VerifyError::Mismatch {
                            expected, actual, ..
                        } => format!(
                            "{} mismatch for '{}': expected {}, got {}",
                            entry.hash_type.as_str(),
                            entry.target,
                            expected,
                            actual
                        ),
                        VerifyError::FileError { error, .. } => format!(
                            "{} target '{}' unreadable: {}",
                            entry.hash_type.as_str(),
                            entry.target,
                            error
                        ),
                        VerifyError::UnboundWorkload { .. } => {
                            unreachable!("the verify stage never binds")
                        }
                    });
                    audit_logger.log(evt);
                    return Err(source);
                }
            };

            if actual_hash != entry.hash_value {
                let mut evt = AuditEvent::new(
                    correlation_id,
                    EventType::HashMismatch,
                    Severity::Critical,
                    Outcome::Failure,
                    Action::Denied,
                );
                evt.target_server = Some(server_name.to_string());
                evt.details = Some(format!(
                    "{} mismatch for '{}': expected {}, got {}",
                    entry.hash_type.as_str(),
                    entry.target,
                    entry.hash_value,
                    actual_hash
                ));
                audit_logger.log(evt);

                return Err(VerifyError::Mismatch {
                    hash_type: entry.hash_type,
                    target: entry.target.clone(),
                    expected: entry.hash_value.clone(),
                    actual: actual_hash,
                });
            }

            // Hash matches — emit success event
            let mut evt = AuditEvent::new(
                correlation_id,
                EventType::HashVerified,
                Severity::Info,
                Outcome::Success,
                Action::Allowed,
            );
            evt.target_server = Some(server_name.to_string());
            evt.details = Some(format!(
                "{} verified for '{}'",
                entry.hash_type.as_str(),
                entry.target
            ));
            audit_logger.log(evt);

            if let Some(held) = held {
                self.pins.push((i, held));
            }
        }

        Ok(VerifyResult::Verified)
    }

    /// The held pin minted for `hash_entries[index]` — `None` when the
    /// entry carries no launch identity (lockfile/docker) or the
    /// workload was verified against a different slice.
    pub(super) fn pin_for(&mut self, index: usize) -> Option<&mut HeldTarget> {
        self.pins
            .iter_mut()
            .find(|(i, _)| *i == index)
            .map(|(_, held)| held)
    }

    /// Take the held pin minted for `hash_entries[index]` — the spawn
    /// pin consumes the handle outright.
    pub(super) fn take_pin(&mut self, index: usize) -> Option<HeldTarget> {
        self.pins
            .iter()
            .position(|(i, _)| *i == index)
            .map(|pos| self.pins.remove(pos).1)
    }
}

impl HeldTarget {
    /// Mint the verify-stage pin for `entry`: open `path` on the
    /// replacement-preventing share mode (Windows) or the identity
    /// anchor fd (Unix), stamp it, hash the held object, and prove the
    /// stamp held across the read so a mid-read rewrite cannot mint a
    /// pin over hybrid bytes.
    fn mint(entry: &HashEntry, path: &Path) -> Result<Self, VerifyError> {
        let mut held = Self::open_fresh(path, entry.hash_type, entry.target.clone())?;
        held.expected = entry.hash_value.clone();
        Ok(held)
    }
}
