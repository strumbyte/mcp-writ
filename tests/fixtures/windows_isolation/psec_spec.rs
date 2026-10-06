//! PSEC flatbuffer spec — a minimal hand-rolled FlatBuffers writer for
//! the public ProcessSecurityEnvironment schema (schema v1.0).

/// Minimal FlatBuffers writer for the public
/// `external/windows-sdk/ProcessSecurityEnvironment.fbs` schema
/// (`file_identifier "PSEC"`, `root_type ProcessSecurityEnvironment`).
///
/// The wire-format rule that matters here: a `uoffset` field must point
/// *forward* — to a higher buffer position than the field slot — so a
/// table's referenced children are laid out after the table itself
/// (the vtable still precedes its table; that offset is the signed
/// `soffset`). This builder therefore writes parents first and patches
/// reference slots once each child's position is known.
struct Fb {
    buf: Vec<u8>,
}

impl Fb {
    /// `with_ident` writes the schema's `file_identifier "PSEC"` at
    /// bytes 4..8; without it the root uoffset leads the buffer.
    fn new(with_ident: bool) -> Self {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(&0u32.to_le_bytes());
        if with_ident {
            buf.extend_from_slice(b"PSEC");
        }
        Fb { buf }
    }

    fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
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

/// The spec nodes this probe encodes.
enum SpecNode {
    Str(String),
    StrVec(Vec<String>),
    /// Vector of offsets to tables (e.g. `[EndpointRule]`).
    TabVec(Vec<SpecNode>),
    Table {
        max_slot: usize,
        fields: Vec<(usize, FieldV)>,
    },
}

enum FieldV {
    U8(u8),
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
        SpecNode::StrVec(items) => {
            fb.align(4);
            let pos = fb.pos();
            fb.buf
                .extend_from_slice(&(items.len() as u32).to_le_bytes());
            let mut slots = Vec::with_capacity(items.len());
            for _ in items {
                slots.push(fb.pos() as usize);
                fb.buf.extend_from_slice(&0u32.to_le_bytes());
            }
            // Elements forward-reference the strings written right after.
            for (slot, s) in slots.iter().zip(items.iter()) {
                let sp = write_node(fb, &SpecNode::Str(s.clone()));
                fb.patch_u32(*slot, sp - *slot as u32);
            }
            pos
        }
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
                while cursor % 4 != 0 {
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

/// Root the buffer at `node` and return the finished bytes.
fn fb_finish(mut fb: Fb, node: &SpecNode) -> Vec<u8> {
    let root = write_node(&mut fb, node);
    fb.patch_u32(0, root);
    fb.buf
}

/// Network posture encoded into `network_policy` (root slot 7).
pub(crate) enum NetSpec {
    /// No network_policy field at all.
    None,
    /// `egress = { default_action: deny }` — the deny byte is written
    /// explicitly so a refused connect is on the wire, not a schema
    /// default.
    DenyAll,
    /// `egress = { default_action: deny, allow: [{destinations:
    /// [{subnet: {addr, prefix 32}}], ports: [{tcp, port}]}] }` — a
    /// pinned destination/port rule so an allowed connect and a denied
    /// connect can be told apart.
    AllowOnly { addr: String, port: u16 },
}

fn net_policy_node(spec: &NetSpec) -> SpecNode {
    let mut egress_fields: Vec<(usize, FieldV)> = vec![(0, FieldV::U8(0))];
    if let NetSpec::AllowOnly { addr, port } = spec {
        // IpSubnet{ address, prefix_length }
        let subnet = SpecNode::Table {
            max_slot: 1,
            fields: vec![
                (0, FieldV::Ref(Box::new(SpecNode::Str(addr.clone())))),
                (1, FieldV::U8(32)),
            ],
        };
        // DestinationRule{ subnet }
        let dest = SpecNode::Table {
            max_slot: 1,
            fields: vec![(0, FieldV::Ref(Box::new(subnet)))],
        };
        // PortRule{ protocol: tcp(1), port }
        let port_rule = SpecNode::Table {
            max_slot: 2,
            fields: vec![(0, FieldV::U8(1)), (1, FieldV::U16(*port))],
        };
        // EndpointRule{ destinations: [..], ports: [..] }
        let rule = SpecNode::Table {
            max_slot: 1,
            fields: vec![
                (0, FieldV::Ref(Box::new(SpecNode::TabVec(vec![dest])))),
                (1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![port_rule])))),
            ],
        };
        // EndpointPolicy{ default_action: deny, allow: [rule] }
        egress_fields.push((1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![rule])))));
    }
    let egress = SpecNode::Table {
        max_slot: 2,
        fields: egress_fields,
    };
    // NetworkPolicy{ egress } — egress is vtable slot 1.
    SpecNode::Table {
        max_slot: 3,
        fields: vec![(1, FieldV::Ref(Box::new(egress)))],
    }
}

/// Build a PSEC spec (`file_identifier "PSEC"`, schema v1.0).
pub(crate) fn psec_spec(
    ro: &[String],
    rw: &[String],
    deny: &[String],
    net: &NetSpec,
    ident: bool,
) -> Vec<u8> {
    let mut fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(1, 0))];
    if !rw.is_empty() {
        // fs_read_write — slot 4.
        fields.push((4, FieldV::Ref(Box::new(SpecNode::StrVec(rw.to_vec())))));
    }
    if !ro.is_empty() {
        // fs_read_only — slot 5.
        fields.push((5, FieldV::Ref(Box::new(SpecNode::StrVec(ro.to_vec())))));
    }
    if !deny.is_empty() {
        // fs_deny — slot 6.
        fields.push((6, FieldV::Ref(Box::new(SpecNode::StrVec(deny.to_vec())))));
    }
    if !matches!(net, NetSpec::None) {
        fields.push((7, FieldV::Ref(Box::new(net_policy_node(net)))));
    }
    let root = SpecNode::Table {
        max_slot: 8,
        fields,
    };
    fb_finish(Fb::new(ident), &root)
}

/// Bare-bones spec: version only (+ optional ident).
pub(crate) fn psec_spec_minimal(ident: bool, minor: u16) -> Vec<u8> {
    let root = SpecNode::Table {
        max_slot: 8,
        fields: vec![(0, FieldV::Ver(1, minor))],
    };
    fb_finish(Fb::new(ident), &root)
}
