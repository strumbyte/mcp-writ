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
//! endpoint forms, ingress rules, and IPv6 destinations (only IPv4
//! subnet strings were verified). Every emitted endpoint allow rule pins
//! `protocol: tcp` across the whole port range — an endpoint without a
//! `ports` clause is transport-blind and would widen the policy model's
//! TCP-only allow rules to UDP. Per-port and non-TCP qualifiers refuse
//! at load/policy-check rather than emitting shapes the measured host
//! did not exercise.
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
    /// names first (a measured transient `PATH_NOT_FOUND` answer on cold
    /// name resolution, surfaced as an HRESULT or NTSTATUS code) and
    /// reports them on failure.
    pub fs_paths: Vec<String>,
    pub grants: Vec<ProcessGrant>,
}

use crate::policy::validator::{
    NAME_LAYER_GUIDANCE, entry_needs_name_layer, psec_fs_path_expressible, psec_ipv4_expressible,
};

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
///   `allowed` entries become destination rules pinned to TCP across
///   every port; any other spelling refuses, as do `port=`/`proto=`
///   qualifiers the TCP pin cannot express. `denied_hosts` entries
///   stay `Skipped` — every destination is already denied by the
///   default action, and the RPC layer keeps its own checks.
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
        // Entries written `host:port` (or the URL/bracketed spellings)
        // folded the port away at parse — the recorded spelling refuses
        // here rather than silently emitting an every-port allow rule.
        // Only a record whose folded host is still an allow entry counts,
        // matching the load-time validator's contract.
        for raw in &policy.network.outbound.allowed_port_qualified {
            if !policy
                .network
                .outbound
                .allowed
                .contains(&crate::policy::host::normalize_policy_host(raw))
            {
                continue;
            }
            // A port-qualified *name* entry additionally carries the
            // name-layer guidance — no native-Windows name layer exists
            // even for an unqualified hostname.
            let name_guidance = if entry_needs_name_layer(raw) {
                format!("; {NAME_LAYER_GUIDANCE}")
            } else {
                Default::default()
            };
            problems.push(format!(
                "outbound allow entry '{raw}' carries an explicit port — \
                 a PSEC egress destination covers every port to the \
                 address and cannot express the qualifier{name_guidance}"
            ));
            push(
                GrantSubject::Rule {
                    kind: "net_destination",
                    name: raw.clone(),
                },
                GrantOrigin::Policy,
                ControlState::NotApplied,
                Some(
                    "port qualifier cannot be expressed — would widen to \
                     every port"
                        .to_string(),
                ),
            );
        }
        for entry in &policy.network.outbound.allowed {
            if policy
                .network
                .outbound
                .allowed_port_qualified
                .iter()
                .any(|raw| crate::policy::host::normalize_policy_host(raw) == *entry)
            {
                continue;
            }
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
                        "PSEC egress allow rule (IPv4 destination pinned to \
                         TCP — every TCP port to the destination is allowed)"
                            .to_string(),
                    ),
                );
            } else {
                // Name entries carry the FQDN guidance — the launch-path
                // refusal points at the same routes the load-time
                // validator names.
                let name_guidance = if entry_needs_name_layer(entry) {
                    format!("; {NAME_LAYER_GUIDANCE}")
                } else {
                    Default::default()
                };
                problems.push(format!(
                    "outbound allow entry '{entry}' is not an IPv4 literal — \
                     a PSEC egress destination is an IP subnet; hostnames, \
                     wildcards and IPv6 spellings have no verified \
                     representation{name_guidance}"
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
        // `cidr` entries carrying a `:port` qualifier — same refusal
        // contract as `allowed_port_qualified`.
        for raw in &policy.network.outbound.allowed_cidrs_port_qualified {
            let still_present = crate::policy::host::analyze_policy_cidr(raw)
                .map(|(cidr, _, _)| policy.network.outbound.allowed_cidrs.contains(&cidr))
                .unwrap_or(false);
            if !still_present {
                continue;
            }
            problems.push(format!(
                "outbound cidr entry '{raw}' carries an explicit port — a \
                 PSEC egress rule pins TCP across every port to the \
                 destination and cannot express the qualifier"
            ));
            push(
                GrantSubject::Rule {
                    kind: "net_destination_cidr",
                    name: raw.clone(),
                },
                GrantOrigin::Policy,
                ControlState::NotApplied,
                Some(
                    "port qualifier cannot be expressed — would widen to \
                     every port"
                        .to_string(),
                ),
            );
        }
        // Structured-rule qualifiers without spelling-level provenance
        // — `port=` attributes, bare-port rules (`allow host="443"` is
        // a port-only grant), and `proto=` — refuse for the same
        // reason: the emitted rule pins TCP over the whole port range,
        // so a narrower port or a different transport cannot be scoped.
        for rule in policy.network.outbound.egress_rules() {
            if !rule.allow {
                continue;
            }
            let proto_qualified = rule.proto != crate::policy::EgressProto::Tcp;
            if !proto_qualified && rule.port.is_none() {
                continue;
            }
            // A rule whose port was already refused via the spelled
            // `host:port`/`cidr:port` provenance is not refused twice.
            let provenance_covered = rule.port.is_some()
                && !proto_qualified
                && match &rule.dest {
                    crate::policy::EgressDest::Host(h) => policy
                        .network
                        .outbound
                        .allowed_port_qualified
                        .iter()
                        .any(|raw| {
                            let (norm, p, _) = crate::policy::host::analyze_policy_host(raw);
                            norm == *h && p.is_some()
                        }),
                    crate::policy::EgressDest::Cidr(c) => policy
                        .network
                        .outbound
                        .allowed_cidrs_port_qualified
                        .iter()
                        .any(|raw| {
                            crate::policy::host::analyze_policy_cidr(raw)
                                .map(|(norm, p, _)| norm == *c && p.is_some())
                                .unwrap_or(false)
                        }),
                    crate::policy::EgressDest::Unix(_) => false,
                };
            if provenance_covered {
                continue;
            }
            problems.push(format!(
                "outbound allow rule '{}' carries a port or protocol \
                 qualifier — a PSEC egress rule pins TCP over every port \
                 to the destination and cannot express it",
                rule.describe()
            ));
            push(
                GrantSubject::Rule {
                    kind: "net_destination",
                    name: rule.describe(),
                },
                GrantOrigin::Policy,
                ControlState::NotApplied,
                Some(
                    "port/proto qualifier cannot be expressed — the \
                     endpoint grants TCP to every port"
                        .to_string(),
                ),
            );
        }
        // The IP layer: `allow cidr=` entries plus IP literals in
        // `allowed` (a literal stands as a `/32` host route — the form
        // the `allowed` loop above already encoded; deduplicate here).
        for entry in &policy.network.outbound.allowed_cidrs {
            // A folded rule whose source spelling carried a `:port`
            // was already refused above — recording a Planned grant
            // for it too would double-count one rule.
            if policy
                .network
                .outbound
                .allowed_cidrs_port_qualified
                .iter()
                .any(|raw| {
                    crate::policy::host::analyze_policy_cidr(raw)
                        .map(|(cidr, _, _)| cidr == *entry)
                        .unwrap_or(false)
                })
            {
                continue;
            }
            if let Some((std::net::IpAddr::V4(addr), 32)) =
                crate::policy::host::parse_policy_cidr(entry)
            {
                let rule = addr.to_string();
                if !allow_rules.contains(&rule) {
                    allow_rules.push(rule);
                }
                push(
                    GrantSubject::Rule {
                        kind: "net_destination_cidr",
                        name: entry.clone(),
                    },
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    Some(
                        "PSEC egress allow rule (IPv4 /32 host route pinned to \
                         TCP — every TCP port to the destination is allowed)"
                            .to_string(),
                    ),
                );
            } else {
                problems.push(format!(
                    "outbound cidr entry '{entry}' is not an IPv4 /32 — a PSEC \
                     egress destination is an IPv4 subnet host route; wider \
                     prefixes and IPv6 have no verified representation"
                ));
                push(
                    GrantSubject::Rule {
                        kind: "net_destination_cidr",
                        name: entry.clone(),
                    },
                    GrantOrigin::Policy,
                    ControlState::NotApplied,
                    Some(
                        "not an IPv4 /32 — inexpressible as a PSEC egress \
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
        for entry in &policy.network.outbound.denied_cidrs {
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
        // PSEC has no except-form: a deny overlapping a declared allow
        // would be silently swallowed by the encoded rule. Checked on
        // the *declared* lists — a programmatically built policy has not
        // necessarily passed through deny-precedence pruning, and a
        // deny-covered allow emitted anyway would invert the deny.
        let denied_ip = policy.network.outbound.ip_layer_denies();
        for allow in policy
            .network
            .outbound
            .allowed
            .iter()
            .filter_map(|h| {
                h.parse::<std::net::IpAddr>()
                    .ok()
                    .map(crate::policy::host::ip_literal_cidr)
            })
            .chain(policy.network.outbound.allowed_cidrs.iter().cloned())
        {
            if denied_ip
                .iter()
                .any(|deny| crate::policy::host::cidr_intersects(deny, &allow))
            {
                problems.push(format!(
                    "outbound allow '{allow}' overlaps an IP-layer deny rule — \
                     PSEC cannot carve an exception out of an allowed \
                     destination; narrow the ranges"
                ));
            }
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
    let mut fs_path_grant = |subject: GrantSubject, path_str: &str, bucket: &mut Vec<String>| {
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
                bucket.push(path_str.to_string());
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
    };
    for (list, access, writable) in [
        (&policy.fs.read_only, FsAccess::Read, false),
        (&policy.fs.read_write, FsAccess::ReadWrite, true),
        // exec-mode paths are read-grants on the PSEC wire (Windows
        // gates exec by readability) but report Execute access.
        (&policy.fs.executable, FsAccess::Execute, false),
    ] {
        let bucket = if writable { &mut rw } else { &mut ro };
        for path_str in list {
            let subject = GrantSubject::FsPath {
                path: path_str.clone(),
                access,
            };
            fs_path_grant(subject, path_str, bucket);
        }
    }
    // Deny entries are deny rules, not access grants — recorded under a
    // `fs_deny` rule kind so the report never reads a denial as a
    // traverse grant.
    for path_str in &policy.fs.denied_paths {
        let subject = GrantSubject::Rule {
            kind: "fs_deny",
            name: path_str.clone(),
        };
        fs_path_grant(subject, path_str, &mut deny);
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
    /// u16 scalar (PortRule `port` / `end_port`).
    U16(u16),
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
                    FieldV::U16(_) => 2,
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
                    FieldV::U16(v) => {
                        fb.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
                    }
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
/// `EndpointRule{ destinations:[{subnet:{address, prefix_length:32}}],
/// ports:[{protocol:tcp, port:1, end_port:65535}] }` (slots 0/1). The
/// port rule pins the grant to TCP across every connectable port: an
/// endpoint without a `ports` clause is transport-blind and would widen
/// the policy model's TCP-only allow rules to UDP. The measured host
/// honoured the field (the winiso `psec-run` golden: a connect to the
/// allowed port was released by the filter while a same-destination
/// connect to an unlisted port returned WSAEACCES). Per-port and
/// non-TCP qualifiers still refuse upstream rather than emitting shapes
/// the host was not measured on.
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
                // PortRule{ protocol: tcp(1), port: 1, end_port: 65535 } —
                // same table shape the measured fixture emitted; the full
                // range keeps the policy model's port-blind scope.
                let port_rule = SpecNode::Table {
                    max_slot: 2,
                    fields: vec![
                        (0, FieldV::U8(1)),
                        (1, FieldV::U16(1)),
                        (2, FieldV::U16(u16::MAX)),
                    ],
                };
                SpecNode::Table {
                    max_slot: 1,
                    fields: vec![
                        (0, FieldV::Ref(Box::new(SpecNode::TabVec(vec![dest])))),
                        (1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![port_rule])))),
                    ],
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

/// The `version` pair the encoder writes at root slot 0 — the audit
/// surface reports it as `enforcement::PSEC_SPEC_SCHEMA_VERSION`; the
/// test below keeps the two spellings in lockstep.
const SPEC_VERSION: (u16, u16) = (1, 0);

/// Encode the translated spec — `file_identifier "PSEC"`, `version`
/// [`SPEC_VERSION`], fs lists at slots 4/5/6, `network_policy` at
/// slot 7. The egress posture is always present and always
/// deny-by-default: a PSEC launch either carries the explicit deny or
/// refuses upstream, so the spec can never accidentally request the
/// inert allow-default.
fn encode_spec(ro: &[String], rw: &[String], deny: &[String], allow_ipv4: &[String]) -> Vec<u8> {
    let mut fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(SPEC_VERSION.0, SPEC_VERSION.1))];
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
mod tests;
