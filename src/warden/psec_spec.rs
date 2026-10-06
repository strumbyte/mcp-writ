//! PSEC spec encoding — the FlatBuffers v1.0 `ProcessSecurityEnvironment`
//! document a policy launch compiles to, plus the policy→spec translation
//! that refuses requirements the mechanism cannot express.
//!
//! The schema is the public
//! `external/windows-sdk/ProcessSecurityEnvironment.fbs` (`file_identifier
//! "PSEC"`, `root_type ProcessSecurityEnvironment`) in the v1.0 wire shape
//! validated on the measured host (see `docs/validation/windows-isolation.md`):
//! root table slot 0 carries the inline `version` struct, slots 4/5/6 are the
//! `fs_read_write` / `fs_read_only` / `fs_deny` string vectors, and slot 7 is
//! `network_policy` whose `egress` endpoint policy takes `default_action`
//! (slot 0) and `allow` endpoint rules (slot 1).
//!
//! Deliberately absent from the encoding — no evidence supports them on the
//! measured build and a field the server does not understand is never
//! silently emitted: `capabilities`, `ui_restrictions`,
//! `disallow_win32k_system_calls` (v2 fields), the `deny`/`except`
//! endpoint forms, port rules (the policy model carries no port identity —
//! a `host:port` entry's port is normalized away at parse), ingress rules,
//! and IPv6 destinations (only IPv4 subnet strings were verified).
//!
//! This module is pure data transformation — no Win32 — so the encoder and
//! the translation refusals are testable on every platform.

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::policy::Policy;

// ---------------------------------------------------------------------------
// Policy → spec translation
// ---------------------------------------------------------------------------

/// One refusal reason inside [`PsecRefusal`].
#[derive(Debug)]
pub(crate) struct PsecRefusal {
    /// Every inexpressible policy requirement found — refused launches
    /// name all of them, not just the first.
    pub problems: Vec<String>,
    /// The grant records describing what the spec would have carried;
    /// refused entries are `NotApplied` with their own reason.
    pub grants: Vec<ProcessGrant>,
}

/// The encoded spec plus the launch-report grant entries describing it.
pub(crate) struct PsecBuild {
    pub spec: Vec<u8>,
    /// Every fs path the spec encodes — the create call warms these
    /// names first (a measured transient `STATUS_OBJECT_PATH_NOT_FOUND`
    /// on cold name resolution) and reports them on failure.
    pub fs_paths: Vec<String>,
    pub grants: Vec<ProcessGrant>,
}

use crate::policy::validator::psec_ipv4_expressible;

/// Whether a policy fs path can appear in a PSEC fs list: a literal,
/// absolute Windows path (drive-letter or UNC). Globs are not expanded
/// by the mechanism; a relative or drive-relative spelling would resolve
/// against an undefined base inside the server-side check.
fn psec_fs_path_expressible(path: &str) -> Result<(), String> {
    if path.contains(['*', '?']) {
        return Err("PSEC filesystem rules are literal paths — glob \
                    characters are never expanded"
            .to_string());
    }
    // Drive-letter absolute (`X:\…`, `X:/…`) or rooted UNC
    // (`\\server\share\…`). Checked by explicit Windows syntax, not
    // `Path::is_absolute` — this module compiles on every platform and
    // the host's path rules must never decide what the Windows-side
    // server would resolve.
    let bytes = path.as_bytes();
    let drive_abs = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc_abs = path.starts_with("\\\\") || path.starts_with("//");
    if !drive_abs && !unc_abs {
        return Err("PSEC filesystem rules need an absolute Windows path \
                    (drive-letter or UNC) — a relative spelling would \
                    resolve against an undefined base"
            .to_string());
    }
    Ok(())
}

/// Translate the policy into a PSEC v1.0 spec plus grant records —
/// `Ok` carries the encoded bytes; `Err` lists every inexpressible
/// requirement (the launch refuses before any environment is created).
///
/// Expressibility contract (measured on the build recorded in
/// `docs/validation/windows-isolation.md`):
///
/// - **Filesystem**: `fs.read_only`/`read_write`/`denied_paths` map to
///   the spec's fs lists verbatim; the launch image and its parent
///   directory are appended read-only. Globs and relative paths refuse;
///   a path that does not exist is a `Skipped` grant (nothing to
///   protect yet — same convention as the DACL path).
/// - **Egress**: `deny_all_others` is the only default action the
///   mechanism enforces — an unrestricted-egress policy refuses
///   (`default_action: allow` measured as inert). IPv4-literal
///   `allowed` entries become destination rules; any other spelling
///   refuses. `denied_hosts` entries stay `Skipped` — every destination
///   is already denied by the default action, and the RPC layer keeps
///   its own checks.
/// - **Inbound / loopback**: PSEC v1.0 has no ingress section and no
///   loopback exemption — `inbound.allow_listen` and HTTP transport
///   refuse.
/// - **Environment**: a PSEC child receives a mechanism-managed
///   environment; the parent's block cannot be delivered. A bare
///   `restrict` is satisfied structurally, but named variables
///   (`environment.allowed`) and a `tmpdir` override refuse.
pub(crate) fn build_launch_spec(
    policy: &Policy,
    program: Option<&std::path::Path>,
    command: &str,
    opts: &super::SpawnOptions,
) -> Result<PsecBuild, PsecRefusal> {
    let mut grants: Vec<ProcessGrant> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let mut push = |subject: GrantSubject,
                    origin: GrantOrigin,
                    state: ControlState,
                    reason: Option<String>| {
        grants.push(ProcessGrant {
            subject,
            origin,
            state,
            reason,
        });
    };

    // Environment contract — decided first because its refusal is a
    // spawn-contract matter, not a spec field.
    if !opts.allowed_names.is_empty() {
        problems.push(format!(
            "environment allow list {} cannot be delivered: a PSEC child \
             receives a mechanism-managed environment (the parent's block is \
             not inherited and a custom lpEnvironment is rejected at \
             CreateProcessW)",
            opts.allowed_names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(tmp) = &opts.tmpdir {
        problems.push(format!(
            "tmpdir override '{}' cannot be delivered: TMPDIR/TMP/TEMP \
             cannot be set in a PSEC child's environment",
            tmp.display()
        ));
    }

    // Network — the deny-all default is the only honest posture.
    let mut allow_rules: Vec<String> = Vec::new();
    if !policy.network.outbound.deny_all_others {
        problems.push(
            "unrestricted outbound egress is not expressible: the measured \
             PSEC host applies a deny-all posture to security-environment \
             children and `default_action: allow` did not restore \
             connectivity — the launch refuses rather than silently \
             degrading the network contract"
                .to_string(),
        );
    } else {
        for entry in &policy.network.outbound.allowed {
            if psec_ipv4_expressible(entry) {
                allow_rules.push(entry.clone());
                push(
                    GrantSubject::Rule {
                        kind: "net_destination",
                        name: entry.clone(),
                    },
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    Some(
                        "PSEC egress allow rule (IPv4 destination; the policy \
                         model carries no port semantics — every port to the \
                         destination is allowed)"
                            .to_string(),
                    ),
                );
            } else {
                problems.push(format!(
                    "outbound allow entry '{entry}' is not an IPv4 literal — \
                     a PSEC egress destination is an IP subnet; hostnames, \
                     wildcards and IPv6 spellings have no verified \
                     representation"
                ));
                push(
                    GrantSubject::Rule {
                        kind: "net_destination",
                        name: entry.clone(),
                    },
                    GrantOrigin::Policy,
                    ControlState::NotApplied,
                    Some(
                        "not an IPv4 literal — inexpressible as a PSEC egress \
                         destination"
                            .to_string(),
                    ),
                );
            }
        }
        for entry in &policy.network.outbound.denied_hosts {
            push(
                GrantSubject::Rule {
                    kind: "net_destination_deny",
                    name: entry.clone(),
                },
                GrantOrigin::Policy,
                ControlState::Skipped,
                Some(
                    "covered by the egress default-deny — no explicit deny \
                     rule is emitted (the RPC-layer check still applies)"
                        .to_string(),
                ),
            );
        }
    }
    if policy.network.inbound.allow_listen {
        problems.push(
            "inbound.allow_listen is not expressible: the PSEC v1.0 schema \
             has no ingress section"
                .to_string(),
        );
        push(
            GrantSubject::Rule {
                kind: "net_inbound",
                name: "listen".to_string(),
            },
            GrantOrigin::Policy,
            ControlState::NotApplied,
            Some("no ingress rules in PSEC v1.0".to_string()),
        );
    }
    if matches!(policy.transport.type_, crate::policy::TransportType::Http) {
        problems.push(
            "HTTP transport requires loopback connectivity: egress rules do \
             not exempt loopback (measured) and no loopback exemption exists \
             for a security environment"
                .to_string(),
        );
        push(
            GrantSubject::Rule {
                kind: "loopback_exemption",
                name: "localhost".to_string(),
            },
            GrantOrigin::Runtime,
            ControlState::NotApplied,
            Some("no loopback exemption exists for PSEC".to_string()),
        );
    }

    // Filesystem rules — policy lists then the launch image.
    let mut ro: Vec<String> = Vec::new();
    let mut rw: Vec<String> = Vec::new();
    let mut deny: Vec<String> = Vec::new();
    for (list, access, bucket) in [
        (&policy.fs.read_only, FsAccess::Read, &mut ro),
        (&policy.fs.read_write, FsAccess::ReadWrite, &mut rw),
        (&policy.fs.denied_paths, FsAccess::Traverse, &mut deny),
    ] {
        for path_str in list {
            let subject = GrantSubject::FsPath {
                path: path_str.clone(),
                access,
            };
            match psec_fs_path_expressible(path_str) {
                Err(reason) => {
                    problems.push(format!("fs path '{path_str}': {reason}"));
                    push(
                        subject,
                        GrantOrigin::Policy,
                        ControlState::NotApplied,
                        Some(reason),
                    );
                }
                Ok(()) if std::path::Path::new(path_str).exists() => {
                    bucket.push(path_str.clone());
                    push(subject, GrantOrigin::Policy, ControlState::Planned, None);
                }
                Ok(()) => {
                    push(
                        subject,
                        GrantOrigin::Policy,
                        ControlState::Skipped,
                        Some("path does not exist; no spec entry is emitted".to_string()),
                    );
                }
            }
        }
    }

    // The launch image and its parent — readable inside the environment
    // (the mechanism grants no implicit traversal for the child image's
    // own directory).
    let exe = program
        .map(|p| Some(p.to_path_buf()))
        .unwrap_or_else(|| crate::workload::resolve_command_path(command).ok());
    match exe {
        Some(exe) if exe.is_file() => {
            let exe_s = exe.to_string_lossy().into_owned();
            ro.push(exe_s.clone());
            push(
                GrantSubject::FsPath {
                    path: exe_s,
                    access: FsAccess::Read,
                },
                GrantOrigin::Runtime,
                ControlState::Planned,
                Some("executable image".to_string()),
            );
            if let Some(parent) = exe.parent().filter(|p| p.is_dir()) {
                let parent_s = parent.to_string_lossy().into_owned();
                ro.push(parent_s.clone());
                push(
                    GrantSubject::FsPath {
                        path: parent_s,
                        access: FsAccess::Read,
                    },
                    GrantOrigin::Runtime,
                    ControlState::Planned,
                    Some("ancestor of the executable image".to_string()),
                );
            }
        }
        Some(_) => push(
            GrantSubject::FsPath {
                path: exe
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                access: FsAccess::Read,
            },
            GrantOrigin::Runtime,
            ControlState::Skipped,
            Some("resolved executable is not a file".to_string()),
        ),
        None => push(
            GrantSubject::FsPath {
                path: command.to_string(),
                access: FsAccess::Read,
            },
            GrantOrigin::Runtime,
            ControlState::Skipped,
            Some(
                "executable image could not be resolved — the unresolvable \
                 intent is recorded, not dropped"
                    .to_string(),
            ),
        ),
    }

    if !problems.is_empty() {
        return Err(PsecRefusal { problems, grants });
    }

    let spec = encode_spec(&ro, &rw, &deny, &allow_rules);
    let mut fs_paths = ro;
    fs_paths.extend(rw);
    fs_paths.extend(deny);
    Ok(PsecBuild {
        spec,
        fs_paths,
        grants,
    })
}

// ---------------------------------------------------------------------------
// FlatBuffers writer — the measured v1.0 wire layout
// ---------------------------------------------------------------------------

/// Minimal FlatBuffers writer for the v1.0 schema. The wire-format rule
/// that matters: a `uoffset` field must point *forward* — to a higher
/// buffer position than the field slot — so a table's referenced
/// children are laid out after the table itself (the vtable still
/// precedes its table; that offset is the signed `soffset`). Parents are
/// therefore written first and reference slots patched once each child's
/// position is known.
struct Fb {
    buf: Vec<u8>,
}

impl Fb {
    fn new() -> Self {
        // u32 root offset placeholder + `file_identifier "PSEC"`.
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(b"PSEC");
        Fb { buf }
    }

    fn align(&mut self, a: usize) {
        while !self.buf.len().is_multiple_of(a) {
            self.buf.push(0);
        }
    }

    fn pos(&self) -> u32 {
        self.buf.len() as u32
    }

    fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

enum SpecNode {
    Str(String),
    StrVec(Vec<String>),
    /// Vector of offsets to tables (`[DestinationRule]`, `[EndpointRule]`).
    TabVec(Vec<SpecNode>),
    Table {
        max_slot: usize,
        fields: Vec<(usize, FieldV)>,
    },
}

enum FieldV {
    U8(u8),
    /// Inline `SchemaVersion` struct: {major u16, minor u16}.
    Ver(u16, u16),
    Ref(Box<SpecNode>),
}

/// Write `node` at the buffer end; children of Ref fields follow
/// immediately so every uoffset points forward. Returns the node pos.
fn write_node(fb: &mut Fb, node: &SpecNode) -> u32 {
    match node {
        SpecNode::Str(s) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
            fb.buf.extend_from_slice(s.as_bytes());
            fb.buf.push(0);
            pos
        }
        // StrVec and TabVec share the wire shape: u32 length, then
        // forward-referencing slots — strings and tables alike are
        // children written after the vector.
        SpecNode::StrVec(items) => write_node(
            fb,
            &SpecNode::TabVec(items.iter().cloned().map(SpecNode::Str).collect()),
        ),
        SpecNode::TabVec(items) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf
                .extend_from_slice(&(items.len() as u32).to_le_bytes());
            let mut slots = Vec::with_capacity(items.len());
            for _ in items {
                slots.push(fb.pos() as usize);
                fb.buf.extend_from_slice(&0u32.to_le_bytes());
            }
            for (slot, s) in slots.iter().zip(items.iter()) {
                let sp = write_node(fb, s);
                fb.patch_u32(*slot, sp - *slot as u32);
            }
            pos
        }
        SpecNode::Table { max_slot, fields } => {
            // Field layout: 4-aligned packing after the i32 soffset.
            let mut offs: Vec<u16> = Vec::with_capacity(fields.len());
            let mut cursor: usize = 4;
            for (_slot, f) in fields {
                while !cursor.is_multiple_of(4) {
                    cursor += 1;
                }
                offs.push(cursor as u16);
                cursor += match f {
                    FieldV::U8(_) => 1,
                    FieldV::Ver(..) | FieldV::Ref(_) => 4,
                };
            }
            let table_size = ((cursor + 3) & !3) as u16;
            let vlen = (4 + 2 * (max_slot + 1)) as u16;

            // vtable first (must precede the table in the buffer).
            fb.align(4);
            let vpos = fb.pos() as usize;
            fb.buf.extend_from_slice(&vlen.to_le_bytes());
            fb.buf.extend_from_slice(&table_size.to_le_bytes());
            for s in 0..=*max_slot {
                let off = fields
                    .iter()
                    .zip(offs.iter())
                    .find(|((slot, _), _)| *slot == s)
                    .map(|(_, o)| *o)
                    .unwrap_or(0u16);
                fb.buf.extend_from_slice(&off.to_le_bytes());
            }
            fb.align(4);
            let tpos = fb.pos() as usize;
            fb.buf.resize(tpos + table_size as usize, 0);
            let soffset = (tpos - vpos) as i32;
            fb.buf[tpos..tpos + 4].copy_from_slice(&soffset.to_le_bytes());
            // Scalars in place; each Ref child is written right after the
            // table (forward uoffset) and its slot patched.
            let mut ref_fields: Vec<(usize, &SpecNode)> = Vec::new();
            for ((_slot, f), off) in fields.iter().zip(offs.iter()) {
                let at = tpos + *off as usize;
                match f {
                    FieldV::U8(v) => fb.buf[at] = *v,
                    FieldV::Ver(a, b) => {
                        fb.buf[at..at + 2].copy_from_slice(&a.to_le_bytes());
                        fb.buf[at + 2..at + 4].copy_from_slice(&b.to_le_bytes());
                    }
                    FieldV::Ref(child) => ref_fields.push((at, child)),
                }
            }
            for (at, child) in ref_fields {
                let cp = write_node(fb, child);
                fb.patch_u32(at, cp - at as u32);
            }
            tpos as u32
        }
    }
}

/// `NetworkPolicy{ egress }` — egress is vtable slot 1. `default_action:
/// deny` (0) is written explicitly; each IPv4 destination becomes one
/// `EndpointRule{ destinations:[{subnet:{address, prefix_length:32}}] }`
/// (slot 1). Port rules are never emitted — the policy model carries no
/// port identity, so an allow rule covers every port to the destination.
fn net_policy_node(allow: &[String]) -> SpecNode {
    let mut egress_fields: Vec<(usize, FieldV)> = vec![(0, FieldV::U8(0))];
    if !allow.is_empty() {
        let rules = allow
            .iter()
            .map(|addr| {
                let subnet = SpecNode::Table {
                    max_slot: 1,
                    fields: vec![
                        (0, FieldV::Ref(Box::new(SpecNode::Str(addr.clone())))),
                        (1, FieldV::U8(32)),
                    ],
                };
                let dest = SpecNode::Table {
                    max_slot: 1,
                    fields: vec![(0, FieldV::Ref(Box::new(subnet)))],
                };
                SpecNode::Table {
                    max_slot: 1,
                    fields: vec![(0, FieldV::Ref(Box::new(SpecNode::TabVec(vec![dest]))))],
                }
            })
            .collect();
        egress_fields.push((1, FieldV::Ref(Box::new(SpecNode::TabVec(rules)))));
    }
    let egress = SpecNode::Table {
        max_slot: 2,
        fields: egress_fields,
    };
    SpecNode::Table {
        max_slot: 3,
        fields: vec![(1, FieldV::Ref(Box::new(egress)))],
    }
}

/// Encode the translated spec — `file_identifier "PSEC"`, `version`
/// 1.0, fs lists at slots 4/5/6, `network_policy` at slot 7. The egress
/// posture is always present and always deny-by-default: a PSEC launch
/// either carries the explicit deny or refuses upstream, so the spec
/// can never accidentally request the inert allow-default.
fn encode_spec(ro: &[String], rw: &[String], deny: &[String], allow_ipv4: &[String]) -> Vec<u8> {
    let mut fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(1, 0))];
    if !rw.is_empty() {
        fields.push((4, FieldV::Ref(Box::new(SpecNode::StrVec(rw.to_vec())))));
    }
    if !ro.is_empty() {
        fields.push((5, FieldV::Ref(Box::new(SpecNode::StrVec(ro.to_vec())))));
    }
    if !deny.is_empty() {
        fields.push((6, FieldV::Ref(Box::new(SpecNode::StrVec(deny.to_vec())))));
    }
    fields.push((7, FieldV::Ref(Box::new(net_policy_node(allow_ipv4)))));
    let root = SpecNode::Table {
        max_slot: 8,
        fields,
    };
    let mut fb = Fb::new();
    let root_pos = write_node(&mut fb, &root);
    fb.patch_u32(0, root_pos);
    fb.buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TransportType;
    use crate::warden::SpawnOptions;

    // -- a flatbuffer reader just wide enough to verify the wire layout --

    fn u16at(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
    }
    fn u32at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    /// Absolute position of table field `slot` (0 when the field is absent).
    fn field_at(b: &[u8], table: usize, slot: usize) -> usize {
        let vtable = table - u32at(b, table) as usize;
        let vlen = u16at(b, vtable) as usize;
        let entry = vtable + 4 + 2 * slot;
        if entry + 2 > vtable + vlen {
            return 0;
        }
        let off = u16at(b, entry) as usize;
        if off == 0 { 0 } else { table + off }
    }
    /// Follow a uoffset field to its target table/string/vector position.
    fn follow(b: &[u8], at: usize) -> usize {
        at + u32at(b, at) as usize
    }
    fn string_at(b: &[u8], at: usize) -> String {
        let len = u32at(b, at) as usize;
        String::from_utf8(b[at + 4..at + 4 + len].to_vec()).unwrap()
    }
    /// `[string]` vector → owned strings.
    fn strvec_at(b: &[u8], at: usize) -> Vec<String> {
        let n = u32at(b, at) as usize;
        (0..n)
            .map(|i| string_at(b, follow(b, at + 4 + 4 * i)))
            .collect()
    }

    #[test]
    fn encode_spec_wire_layout() {
        let ro = vec!["C:\\ro".to_string()];
        let rw = vec!["C:\\rw".to_string(), "C:\\rw2".to_string()];
        let deny = vec!["C:\\deny".to_string()];
        let allow = vec!["10.0.0.1".to_string()];
        let b = encode_spec(&ro, &rw, &deny, &allow);

        // file_identifier + root offset.
        assert_eq!(&b[4..8], b"PSEC");
        let root = u32at(&b, 0) as usize;

        // version = {1,0} inline at slot 0.
        let v = field_at(&b, root, 0);
        assert_eq!((u16at(&b, v), u16at(&b, v + 2)), (1, 0));

        // fs vectors at slots 4/5/6.
        assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 4))), rw);
        assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 5))), ro);
        assert_eq!(strvec_at(&b, follow(&b, field_at(&b, root, 6))), deny);

        // network_policy → egress (slot 1) → default_action 0 + allow rules.
        let net = follow(&b, field_at(&b, root, 7));
        let egress = follow(&b, field_at(&b, net, 1));
        assert_eq!(b[field_at(&b, egress, 0)], 0, "egress default_action=deny");
        let rules = follow(&b, field_at(&b, egress, 1));
        assert_eq!(u32at(&b, rules), 1, "one allow rule");
        let rule = follow(&b, rules + 4);
        let dests = follow(&b, field_at(&b, rule, 0));
        assert_eq!(u32at(&b, dests), 1);
        let dest = follow(&b, dests + 4);
        let subnet = follow(&b, field_at(&b, dest, 0));
        let addr = string_at(&b, follow(&b, field_at(&b, subnet, 0)));
        assert_eq!(addr, "10.0.0.1");
        assert_eq!(b[field_at(&b, subnet, 1)], 32, "prefix_length");
    }

    #[test]
    fn encode_spec_empty_lists_omit_fields_but_keep_deny_default() {
        let b = encode_spec(&[], &[], &[], &[]);
        let root = u32at(&b, 0) as usize;
        for slot in [4usize, 5, 6] {
            assert_eq!(field_at(&b, root, slot), 0, "slot {slot} absent");
        }
        let net = follow(&b, field_at(&b, root, 7));
        let egress = follow(&b, field_at(&b, net, 1));
        assert_eq!(b[field_at(&b, egress, 0)], 0);
        assert_eq!(field_at(&b, egress, 1), 0, "no allow rules");
    }

    fn base_policy() -> Policy {
        Policy::default() // deny_all_others = true
    }

    fn refusal(policy: &Policy, opts: &SpawnOptions) -> Vec<String> {
        match build_launch_spec(policy, None, "child", opts) {
            Ok(_) => panic!("expected refusal"),
            Err(r) => r.problems,
        }
    }

    #[test]
    fn refuses_environment_allow_list_and_tmpdir() {
        let policy = base_policy();
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec!["FOO".to_string()],
            tmpdir: Some(std::path::PathBuf::from("C:\\tmp")),
        };
        let r = match build_launch_spec(&policy, None, "child", &opts) {
            Ok(_) => panic!("expected refusal"),
            Err(r) => r,
        };
        // Refusal grants stay attached — the report records what the
        // spec would have carried.
        let _ = &r.grants;
        assert!(
            r.problems.iter().any(|p| p.contains("'FOO'")),
            "{:?}",
            r.problems
        );
        assert!(
            r.problems.iter().any(|p| p.contains("tmpdir")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn bare_restrict_environment_is_expressible() {
        let policy = base_policy();
        let opts = SpawnOptions {
            restrict_environment: true,
            allowed_names: vec![],
            tmpdir: None,
        };
        // A bare restriction holds by construction — no refusal, and the
        // spec encodes.
        assert!(build_launch_spec(&policy, None, "child", &opts).is_ok());
    }

    #[test]
    fn refuses_unrestricted_egress_and_inbound_and_http() {
        let mut policy = base_policy();
        policy.network.outbound.deny_all_others = false;
        policy.network.inbound.allow_listen = true;
        policy.transport.type_ = TransportType::Http;
        let problems = refusal(&policy, &SpawnOptions::default());
        assert!(
            problems.iter().any(|p| p.contains("unrestricted outbound")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("allow_listen")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("loopback")),
            "{problems:?}"
        );
    }

    #[test]
    fn refuses_non_ipv4_and_port_qualified_allow_entries() {
        let mut policy = base_policy();
        policy.network.outbound.allowed = vec![
            "api.example.com".to_string(),
            "10.0.0.1:443".to_string(),
            "::1".to_string(),
        ];
        let problems = refusal(&policy, &SpawnOptions::default());
        for needle in ["api.example.com", "10.0.0.1:443", "::1"] {
            assert!(
                problems.iter().any(|p| p.contains(needle)),
                "{needle}: {problems:?}"
            );
        }
    }

    #[test]
    fn refuses_glob_and_relative_fs_paths() {
        let mut policy = base_policy();
        policy.fs.read_only = vec!["C:\\data\\**".to_string(), "rel\\path".to_string()];
        let problems = refusal(&policy, &SpawnOptions::default());
        assert!(problems.iter().any(|p| p.contains("glob")), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("absolute")),
            "{problems:?}"
        );
    }

    #[test]
    fn expressible_policy_encodes_ipv4_allow_rules() {
        let mut policy = base_policy();
        policy.network.outbound.allowed = vec!["10.0.0.1".to_string()];
        let build = build_launch_spec(&policy, None, "child", &SpawnOptions::default())
            .expect("expressible");
        // spec carries the egress allow rule (verified structurally above).
        assert!(!build.spec.is_empty());
        // fs_paths is the create-time warm list — read it so the field
        // is exercised even when every fs entry was skipped.
        let _ = &build.fs_paths;
        assert!(build.grants.iter().any(
            |g| matches!(&g.subject, GrantSubject::Rule { kind, name }
                    if *kind == "net_destination" && name == "10.0.0.1")
                && g.state == ControlState::Planned
        ));
    }
}
