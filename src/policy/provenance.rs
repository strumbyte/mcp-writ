//! Composition provenance and load-time warnings.
//!
//! A composed policy is built by layering documents — `extends`, each
//! `include`, the file's own nodes, and matching `when` blocks. This
//! module records, for every field the composition writes, which file
//! wrote it and what the write did (`set` / `union` / `replace` /
//! `prune`). Two consumers use the record:
//!
//! - `mcp-writ policy resolve` prints the composed KDL alongside the
//!   per-field provenance (PR-24, F-17);
//! - `MCP_WRIT_REPLACE_MODE` gates the load-time warnings emitted when
//!   a declaration silently *replaced* entries an earlier file had
//!   written — the F-13 (`defaults.syscalls`), F-14
//!   (`defaults.network` allow side, tool fs/network) and
//!   profile-redefinition losses — and `plan`/`check` carry the same
//!   warnings in their JSON reports.
//!
//! The recorder never changes merge behavior: it observes the same
//! writes the merge performs, tagging each list entry with the file
//! that contributed it so a later replacement can name whose entries
//! were dropped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::PolicyError;

/// The kind of write one declaration performed on the composed policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvOp {
    /// Wrote a field the composed policy did not carry.
    Set,
    /// Added entries to an accumulating list (filesystem unions, deny
    /// lists, integrity entries).
    Union,
    /// Replaced a list wholesale — `replaced` names the files whose
    /// entries were dropped and how many each lost.
    Replace,
    /// Dropped entries that a deny list covers (deny-wins pruning).
    Prune,
}

impl ProvOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Union => "union",
            Self::Replace => "replace",
            Self::Prune => "prune",
        }
    }
}

/// One write the composition performed on a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvRecord {
    /// The field the write touched — `defaults.syscalls`,
    /// `defaults.network.allow`, `server "s".tool "t".filesystem.allow`,
    /// `profile "name"`, ...
    pub field: String,
    /// The file whose declaration performed the write.
    pub file: PathBuf,
    /// 1-based line of the declaring node inside `file` (when known).
    pub line: Option<u32>,
    pub op: ProvOp,
    /// `set`/`union`: the entries written. `replace`/`prune`: the
    /// entries dropped.
    pub items: Vec<String>,
    /// `replace`/`prune`: the files that contributed the dropped
    /// entries and the count each lost.
    pub replaced: Vec<(PathBuf, usize)>,
    /// `replace`/`prune`: the per-item losses `replaced` summarizes —
    /// `(contributing file, dropped item)` — so a diagnostic asking
    /// about one entry names only the files that actually lost it.
    pub dropped: Vec<(PathBuf, String)>,
}

/// The provenance log a policy load produced — attached to the loaded
/// [`Policy`](crate::policy::Policy) so diagnostics issued downstream
/// (the `execve` spawn requirement, `policy resolve`) can name the
/// file that wrote an effective field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyProvenance {
    /// Write log in composition order.
    pub records: Vec<ProvRecord>,
}

impl PolicyProvenance {
    /// The `(file, line)` that last wrote `field`, when recorded.
    pub fn field_writer(&self, field: &str) -> Option<(&Path, Option<u32>)> {
        self.records
            .iter()
            .rev()
            .find(|r| r.field == field)
            .map(|r| (r.file.as_path(), r.line))
    }

    /// The `replaced` warnings the load surfaces — one per
    /// `(replacing file, contributing file)` pair per replace record:
    /// "child.kdl replaced N entries in <field> declared by
    /// base.kdl". Prunes are excluded — a declared deny covering an
    /// allow is the schema's own semantics, not a silent drop.
    pub fn replacement_warnings(&self) -> Vec<LoadWarning> {
        let mut out = Vec::new();
        for rec in &self.records {
            for (prev, n) in &rec.replaced {
                out.push(LoadWarning {
                    kind: LoadWarningKind::Replaced,
                    file: rec.file.clone(),
                    line: rec.line,
                    message: format!(
                        "replaced {n} '{}' entr{} declared by '{}'",
                        rec.field,
                        if *n == 1 { "y" } else { "ies" },
                        prev.display()
                    ),
                });
            }
        }
        out
    }

    /// Files whose declaration of `item` in `field` a later write
    /// dropped — `(contributing file, replacing file)` pairs. Used to
    /// explain *why* an expected entry (e.g. `execve`) is absent.
    /// Filtering is per item: a contributor that lost only other
    /// entries in the same record is not named.
    pub fn dropped_from(&self, field: &str, item: &str) -> Vec<(PathBuf, PathBuf)> {
        let mut out = Vec::new();
        for rec in &self.records {
            if rec.field != field {
                continue;
            }
            for (contributor, lost) in &rec.dropped {
                if lost == item {
                    out.push((contributor.clone(), rec.file.clone()));
                }
            }
        }
        out
    }
}

/// Where a declaration lives — the file plus the 1-based line of the
/// declaring node (when the merge can identify it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclOrigin {
    pub file: PathBuf,
    pub line: Option<u32>,
}

/// The write log plus the live per-field contributor map. `writers`
/// holds, for every list field, the current entries tagged with the
/// file that wrote each — a `replace` computes the dropped entries
/// per contributor, and a `union` leaves earlier contributors tagged
/// so item-level provenance survives include chains.
#[derive(Debug, Default)]
pub(crate) struct Provenance {
    records: Vec<ProvRecord>,
    writers: HashMap<String, Vec<(PathBuf, String)>>,
}

impl Provenance {
    fn push(&mut self, record: ProvRecord) {
        self.records.push(record);
    }

    /// `file` wrote scalar/flag `field` — no entry tracking (the write
    /// log itself is the provenance).
    pub(crate) fn set(&mut self, field: impl Into<String>, file: &Path, line: Option<u32>) {
        self.push(ProvRecord {
            field: field.into(),
            file: file.to_path_buf(),
            line,
            op: ProvOp::Set,
            items: Vec::new(),
            replaced: Vec::new(),
            dropped: Vec::new(),
        });
    }

    /// `file` appended `items` to accumulating list `field`. Entries
    /// already present keep their earlier contributor — an include
    /// merge re-stating an inherited entry does not re-attribute it.
    pub(crate) fn union(
        &mut self,
        field: impl Into<String>,
        file: &Path,
        line: Option<u32>,
        items: impl IntoIterator<Item = String>,
    ) {
        let field = field.into();
        let writers = self.writers.entry(field.clone()).or_default();
        let mut added = Vec::new();
        for item in items {
            if writers.iter().any(|(_, i)| i == &item) {
                continue;
            }
            writers.push((file.to_path_buf(), item.clone()));
            added.push(item);
        }
        if !added.is_empty() {
            self.push(ProvRecord {
                field,
                file: file.to_path_buf(),
                line,
                op: ProvOp::Union,
                items: added,
                replaced: Vec::new(),
                dropped: Vec::new(),
            });
        }
    }

    /// `file` wrote `items` as the complete contents of list `field`.
    /// Entries previously contributed that `items` does not restate are
    /// dropped — recorded per contributing file in `replaced`.
    pub(crate) fn replace(
        &mut self,
        field: impl Into<String>,
        file: &Path,
        line: Option<u32>,
        items: Vec<String>,
    ) {
        let field = field.into();
        let old = self.writers.remove(&field).unwrap_or_default();
        let mut lost: Vec<(PathBuf, String)> = Vec::new();
        let mut new_writers: Vec<(PathBuf, String)> = Vec::new();
        // Dropped entries: present before, absent now. Entries kept
        // stay tagged with the file that wrote them.
        for (contributor, item) in old {
            if items.iter().any(|i| i == &item) {
                new_writers.push((contributor, item));
            } else {
                lost.push((contributor, item));
            }
        }
        for item in &items {
            if !new_writers.iter().any(|(_, i)| i == item) {
                new_writers.push((file.to_path_buf(), item.clone()));
            }
        }
        self.writers.insert(field.clone(), new_writers);
        let op = if lost.is_empty() {
            ProvOp::Set
        } else {
            ProvOp::Replace
        };
        let dropped_items: Vec<String> = lost.iter().map(|(_, i)| i.clone()).collect();
        let replaced = group_by_file(lost.clone());
        self.push(ProvRecord {
            field,
            file: file.to_path_buf(),
            line,
            op,
            items: if op == ProvOp::Replace {
                dropped_items
            } else {
                items
            },
            replaced,
            dropped: lost,
        });
    }

    /// `file` dropped `items` from list `field` (deny-wins pruning).
    /// The contributors who lost entries are recorded in `replaced`;
    /// a prune is a declared deny's consequence, never a warning.
    pub(crate) fn prune(
        &mut self,
        field: impl Into<String>,
        file: &Path,
        line: Option<u32>,
        items: Vec<String>,
    ) {
        if items.is_empty() {
            return;
        }
        let field = field.into();
        let writers = self.writers.entry(field.clone()).or_default();
        let mut lost: Vec<(PathBuf, String)> = Vec::new();
        writers.retain(|(contributor, item)| {
            if items.iter().any(|i| i == item) {
                lost.push((contributor.clone(), item.clone()));
                false
            } else {
                true
            }
        });
        self.push(ProvRecord {
            field,
            file: file.to_path_buf(),
            line,
            op: ProvOp::Prune,
            items,
            replaced: group_by_file(lost.clone()),
            dropped: lost,
        });
    }

    /// `file` redeclared profile `name` that `prev` had defined — the
    /// earlier layer (holding `count` entries) is replaced wholesale.
    pub(crate) fn replace_profile(
        &mut self,
        name: &str,
        file: &Path,
        line: Option<u32>,
        prev: &Path,
        count: usize,
    ) {
        self.push(ProvRecord {
            field: format!("profile {name:?}"),
            file: file.to_path_buf(),
            line,
            op: ProvOp::Replace,
            items: Vec::new(),
            replaced: vec![(prev.to_path_buf(), count)],
            dropped: Vec::new(),
        });
    }

    /// The records a finished load carries on the policy.
    pub(crate) fn finish(self) -> PolicyProvenance {
        PolicyProvenance {
            records: self.records,
        }
    }
}

/// Group `(file, item)` losses into `(file, count)` pairs, preserving
/// first-seen order.
fn group_by_file(lost: Vec<(PathBuf, String)>) -> Vec<(PathBuf, usize)> {
    let mut out: Vec<(PathBuf, usize)> = Vec::new();
    for (file, _) in lost {
        match out.iter_mut().find(|(f, _)| f == &file) {
            Some((_, n)) => *n += 1,
            None => out.push((file, 1)),
        }
    }
    out
}

/// A finding the policy load surfaces without failing the load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadWarning {
    /// `schema` — a v1 laxity the v2 grammar refuses (unknown or
    /// duplicate nodes, malformed `profile`/`extends`/`when`, unknown
    /// transport); `replaced` — an overlay declaration dropped
    /// inherited entries; `inbound` — a `defaults.network`
    /// re-declaration skipped `inbound` while a listener grant stayed
    /// live; `posture` — a declaration weakened a fail-secure setting.
    pub kind: LoadWarningKind,
    /// The file whose declaration the warning names.
    pub file: PathBuf,
    /// 1-based line inside `file` (when known).
    pub line: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadWarningKind {
    Schema,
    Replaced,
    Inbound,
    Posture,
}

impl LoadWarningKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Replaced => "replaced",
            Self::Inbound => "inbound",
            Self::Posture => "posture",
        }
    }
}

/// Everything a policy load learned besides the policy itself — the
/// `// REVIEW` markers `check` reports in-band and the warnings the
/// enforcing loaders print (and `plan`/`check`/`policy resolve` carry
/// in their JSON output).
#[derive(Debug, Default)]
pub struct LoadDiagnostics {
    pub review_markers: Vec<crate::policy::review::ReviewMarker>,
    pub warnings: Vec<LoadWarning>,
}

impl LoadDiagnostics {
    /// The `replaced` warnings — the subset `MCP_WRIT_REPLACE_MODE`
    /// gates (the others are load-time informational output).
    pub fn replace_warnings(&self) -> impl Iterator<Item = &LoadWarning> {
        self.warnings
            .iter()
            .filter(|w| w.kind == LoadWarningKind::Replaced)
    }

    /// Print every warning once on stderr — the `Warning:` style the
    /// existing posture/inbound and REVIEW paths established. File
    /// paths come from `extends`/`include` arguments inside policy
    /// text, so they are sanitized the same way the message is.
    pub fn emit_warnings(&self) {
        for w in &self.warnings {
            let file = crate::termutil::sanitize_for_terminal(&w.file.display().to_string());
            match w.line {
                Some(line) => eprintln!(
                    "Warning: {file}:{line}: {}",
                    crate::termutil::sanitize_for_terminal(&w.message)
                ),
                None => eprintln!(
                    "Warning: {file}: {}",
                    crate::termutil::sanitize_for_terminal(&w.message)
                ),
            }
        }
    }
}

/// What a policy load does with `replaced` warnings — the declarations
/// that silently dropped inherited entries.
///
/// Resolved from `MCP_WRIT_REPLACE_MODE` with the same fail-closed
/// convention as `MCP_WRIT_REVIEW_MODE`: unset/`""`/`warn` prints each
/// replacement and continues (default), `refuse`/`strict` fails the
/// load, `off` silences them, and an unrecognized value fails closed
/// as `Refuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceMode {
    Off,
    Warn,
    Refuse,
}

impl ReplaceMode {
    pub fn from_env() -> Self {
        match std::env::var("MCP_WRIT_REPLACE_MODE") {
            Ok(value) => Self::parse(&value),
            Err(_) => Self::Warn,
        }
    }

    fn parse(value: &str) -> Self {
        match value.trim() {
            "" | "warn" => Self::Warn,
            "refuse" | "strict" => Self::Refuse,
            "off" => Self::Off,
            _ => Self::Refuse,
        }
    }

    /// Apply the mode to the load's `replaced` warnings. `Refuse`
    /// fails the load with a `Validation` error naming the
    /// replacements; the warnings themselves are already printed.
    pub fn enforce(&self, diag: &LoadDiagnostics) -> Result<(), PolicyError> {
        let warnings: Vec<&LoadWarning> = diag.replace_warnings().collect();
        if warnings.is_empty() || matches!(self, Self::Off | Self::Warn) {
            return Ok(());
        }
        Err(PolicyError::Validation(format!(
            "policy declarations replaced inherited entries ({}): {}",
            warnings.len(),
            warnings
                .iter()
                .map(|w| match w.line {
                    Some(line) => format!("{}:{}", w.file.display(), line),
                    None => w.file.display().to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_keeps_earlier_contributors() {
        let mut p = Provenance::default();
        p.union(
            "defaults.filesystem.read_only",
            Path::new("a.kdl"),
            Some(1),
            ["/x".to_string()],
        );
        p.union(
            "defaults.filesystem.read_only",
            Path::new("b.kdl"),
            Some(2),
            ["/x".to_string(), "/y".to_string()],
        );
        let prov = p.finish();
        // `/x` was already attributed to a.kdl — b.kdl's restatement
        // only records `/y`.
        assert_eq!(prov.records.len(), 2);
        assert_eq!(prov.records[1].items, vec!["/y"]);
    }

    #[test]
    fn replace_reports_dropped_entries_per_file() {
        let mut p = Provenance::default();
        p.union(
            "defaults.syscalls",
            Path::new("a.kdl"),
            None,
            ["execve".to_string(), "read".to_string()],
        );
        p.replace(
            "defaults.syscalls",
            Path::new("b.kdl"),
            Some(4),
            vec!["read".to_string(), "write".to_string()],
        );
        let prov = p.finish();
        let rec = &prov.records[1];
        assert_eq!(rec.op, ProvOp::Replace);
        assert_eq!(rec.items, vec!["execve"]);
        assert_eq!(rec.replaced, vec![(PathBuf::from("a.kdl"), 1)]);
        assert_eq!(
            prov.dropped_from("defaults.syscalls", "execve"),
            vec![(PathBuf::from("a.kdl"), PathBuf::from("b.kdl"))]
        );
    }

    #[test]
    fn dropped_from_names_only_the_losing_contributor() {
        // Two contributors lose *different* entries in one replace —
        // asking about `execve` must not name the file that only
        // lost `read`.
        let mut p = Provenance::default();
        p.union(
            "defaults.syscalls",
            Path::new("a.kdl"),
            None,
            ["execve".to_string()],
        );
        p.union(
            "defaults.syscalls",
            Path::new("b.kdl"),
            None,
            ["read".to_string()],
        );
        p.replace(
            "defaults.syscalls",
            Path::new("c.kdl"),
            None,
            vec!["write".to_string()],
        );
        let prov = p.finish();
        assert_eq!(
            prov.dropped_from("defaults.syscalls", "execve"),
            vec![(PathBuf::from("a.kdl"), PathBuf::from("c.kdl"))]
        );
        assert_eq!(
            prov.dropped_from("defaults.syscalls", "read"),
            vec![(PathBuf::from("b.kdl"), PathBuf::from("c.kdl"))]
        );
    }

    #[test]
    fn first_write_via_replace_records_set() {
        let mut p = Provenance::default();
        p.replace(
            "defaults.syscalls",
            Path::new("a.kdl"),
            Some(1),
            vec!["execve".to_string()],
        );
        let prov = p.finish();
        assert_eq!(prov.records[0].op, ProvOp::Set);
        assert!(prov.records[0].replaced.is_empty());
    }

    #[test]
    fn prune_records_dropped_contributors() {
        let mut p = Provenance::default();
        p.union(
            "defaults.filesystem.read_only",
            Path::new("a.kdl"),
            None,
            ["/x".to_string()],
        );
        p.prune(
            "defaults.filesystem.read_only",
            Path::new("b.kdl"),
            None,
            vec!["/x".to_string()],
        );
        let prov = p.finish();
        assert_eq!(prov.records[1].op, ProvOp::Prune);
        assert_eq!(prov.records[1].replaced, vec![(PathBuf::from("a.kdl"), 1)]);
    }

    #[test]
    fn replace_mode_fail_closed_parse() {
        assert_eq!(ReplaceMode::parse(""), ReplaceMode::Warn);
        assert_eq!(ReplaceMode::parse("warn"), ReplaceMode::Warn);
        assert_eq!(ReplaceMode::parse("refuse"), ReplaceMode::Refuse);
        assert_eq!(ReplaceMode::parse("strict"), ReplaceMode::Refuse);
        assert_eq!(ReplaceMode::parse("off"), ReplaceMode::Off);
        assert_eq!(ReplaceMode::parse("bogus"), ReplaceMode::Refuse);
    }
}
