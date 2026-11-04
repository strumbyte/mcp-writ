//! The bind stage: after verifying configured hash entries, the
//! launched argv must name those same objects — the verify-A-exec-B
//! binding — judged against the held pins `VerifiedWorkload` carries,
//! or the historical pathname re-hash for pinless callers.

use std::path::Path;

use uuid::Uuid;

use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
use crate::verifier::hash::{VerifyError, hash_file};
use crate::workload::{
    argv_contains_inline_eval_with_exe, first_payload_arg_with_exe,
    payload_boundary_blocker_with_exe, same_file,
};

use super::workload::VerifiedWorkload;

/// After verifying configured hash entries, require the launched argv to
/// name those same objects — the verify-A-exec-B binding. A `binary-hash`
/// or `entrypoint-hash` target that canonicalizes to the resolved
/// executable is content-proved against its held pin; an
/// `entrypoint-hash` target matching the first payload argument needs
/// the same freshness proof (`same_file` is path correspondence only,
/// so the payload match cannot stand on the path alone).
///
/// `verified` carries the held pins `verify_server_hashes` minted — one
/// per binary/entrypoint target — and the content judgment becomes the
/// held object's identity plus its recorded stamp: a full read happens
/// only when the object provably changed (a retargeted path or a stale
/// stamp — the stamp never substitutes for the digest, it summons it).
/// `None` keeps the historical pathname re-hash for callers holding no
/// pins (`run-image`-style paths and pinless tests).
pub fn bind_launched_workload(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
    verified: Option<&mut VerifiedWorkload>,
) -> Result<(), VerifyError> {
    if hash_entries.is_empty() {
        return Ok(());
    }
    let mut verified = verified;

    let identity_entries: Vec<(usize, &HashEntry)> = hash_entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
        .collect();

    if identity_entries.is_empty() {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "hash entries exist but none are binary-hash or entrypoint-hash; \
                     lockfile/docker hashes cannot bind the launched process"
                .into(),
        });
    }

    if argv_contains_inline_eval_with_exe(argv, Some(resolved_exe)) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "inline evaluation flags (-c/-e/--eval/--command incl. attached \
                 and = spellings, -p/--print on node, -E on perl) are not a \
                 hash-bindable workload"
                .into(),
        });
    }

    // The exe's content digest — read once up front for pinless
    // callers, as before (the eager read also surfaces an unreadable
    // exe as `FileError` even when no entry matches it). With a
    // workload each covering entry's held pin proves the same fact
    // without a read; a stray pinless entry still falls back lazily.
    let mut exe_hash: Option<String> = None;
    if verified.is_none() {
        exe_hash = Some(
            hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                error,
            })?,
        );
    }

    let mut matched_exe = false;
    let mut matched_binary = false;
    for &(i, entry) in &identity_entries {
        let target = Path::new(&entry.target);
        if !same_file(target, resolved_exe) {
            continue;
        }
        match verified.as_deref_mut().and_then(|w| w.pin_for(i)) {
            Some(pin) => pin.revalidate(resolved_exe)?,
            None => {
                let actual = match exe_hash.clone() {
                    Some(h) => h,
                    None => {
                        let h =
                            hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
                                hash_type: HashType::Binary,
                                target: resolved_exe.display().to_string(),
                                error,
                            })?;
                        exe_hash = Some(h.clone());
                        h
                    }
                };
                if entry.hash_value != actual {
                    return Err(VerifyError::Mismatch {
                        hash_type: entry.hash_type,
                        target: entry.target.clone(),
                        expected: entry.hash_value.clone(),
                        actual,
                    });
                }
            }
        }
        matched_exe = true;
        matched_binary |= entry.hash_type == HashType::Binary;
    }

    let has_binary = identity_entries
        .iter()
        .any(|(_, e)| e.hash_type == HashType::Binary);
    if has_binary && !matched_exe {
        let mut evt = AuditEvent::new(
            Uuid::now_v7(),
            EventType::HashMismatch,
            Severity::Critical,
            Outcome::Failure,
            Action::Denied,
        );
        evt.details = Some(format!(
            "launched '{}' is not a verified binary-hash target",
            resolved_exe.display()
        ));
        audit_logger.log(evt);
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "no binary-hash target canonicalizes to the launched executable".into(),
        });
    }

    let payload_arg = first_payload_arg_with_exe(argv, Some(resolved_exe));
    let mut payload_bound = false;
    for &(i, entry) in identity_entries
        .iter()
        .filter(|(_, e)| e.hash_type == HashType::Entrypoint)
    {
        let target = Path::new(&entry.target);
        // An entrypoint pinned at the executable was covered in the
        // identity loop above. A payload match needs its own freshness
        // proof: `same_file` compares canonicalized paths only, so path
        // correspondence alone would let a script swapped in after the
        // first verification launch under the stale pin — the held
        // pin's stamp (or its re-hash when the stamp moves) decides, or
        // the historical pathname read for pinless callers.
        let payload_match = payload_arg.is_some_and(|arg| same_file(Path::new(arg), target));
        let at_exe = same_file(target, resolved_exe);
        let found = at_exe || payload_match;
        if !found {
            // When the payload boundary is ambiguous the target may still
            // be a legitimately launched script — name the blocking option
            // so the report says why the boundary could not be resolved.
            let reason = match payload_boundary_blocker_with_exe(argv, Some(resolved_exe)) {
                Some(flag) => format!(
                    "entrypoint-hash target '{}' cannot be verified — option \
                     '{flag}' leaves the payload boundary ambiguous",
                    entry.target
                ),
                None => format!(
                    "entrypoint-hash target '{}' is not the launched executable or its first payload argument",
                    entry.target
                ),
            };
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason,
            });
        }
        if payload_match && !at_exe {
            payload_bound = true;
            match verified.as_deref_mut().and_then(|w| w.pin_for(i)) {
                Some(pin) => pin.revalidate(target)?,
                None => {
                    let actual = hash_file(target).map_err(|error| VerifyError::FileError {
                        hash_type: HashType::Entrypoint,
                        target: entry.target.clone(),
                        error,
                    })?;
                    if actual != entry.hash_value {
                        return Err(VerifyError::Mismatch {
                            hash_type: entry.hash_type,
                            target: entry.target.clone(),
                            expected: entry.hash_value.clone(),
                            actual,
                        });
                    }
                }
            }
        }
    }

    if payload_bound {
        // A payload-bound entrypoint makes this an interpreted launch:
        // the resolved executable is an interpreter reading a pinned
        // script. It needs its own `binary-hash` — an entrypoint-only
        // policy would execute an unpinned interpreter while the pin
        // list looks satisfied.
        if !matched_binary {
            let mut evt = AuditEvent::new(
                Uuid::now_v7(),
                EventType::HashMismatch,
                Severity::Critical,
                Outcome::Failure,
                Action::Denied,
            );
            evt.details = Some(format!(
                "launched interpreter '{}' has no binary-hash pin",
                resolved_exe.display()
            ));
            audit_logger.log(evt);
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: "an entrypoint-hash pins the payload script, but no \
                         binary-hash binds the resolved interpreter — the \
                         launched image would execute unpinned"
                    .into(),
            });
        }
        // The payload boundary is only proven under a modeled option
        // grammar. A copied or hard-linked interpreter under an
        // unmodeled name reads a code-bearing flag where the generic
        // scan skipped an option, so the pinned script becomes a decoy
        // for code that actually runs — fail closed instead.
        if !crate::workload::exe_grammar_modeled(argv, Some(resolved_exe)) {
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: "an entrypoint-hash pins the payload script, but the \
                         resolved executable has no modeled option grammar — \
                         the payload boundary cannot be proven for a renamed \
                         or unmodeled interpreter"
                    .into(),
            });
        }
    }

    Ok(())
}
