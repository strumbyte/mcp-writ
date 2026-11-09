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
    U64(u64),
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
                    FieldV::U64(_) => 8,
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
                    FieldV::U64(v) => {
                        fb.buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
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
    /// `egress = { default_action: deny, allow: [{destinations:
    /// [{subnet: {addr, prefix}}], ports: [{tcp, port, end_port}]}] }`
    /// — non-/32 prefixes, IPv6 literals, and port ranges (v1.1-era
    /// wire shapes this probe adds on top of the shipped ladder).
    AllowCidr {
        addr: String,
        prefix: u8,
        port: u16,
        end_port: u16,
    },
    /// `egress = { default_action: deny }` plus
    /// `ingress = { default_action, host_loopback }` — the v1.1
    /// ingress policy surface (NetworkPolicy slot 3).
    DenyAllIngress {
        default_action: u8,
        host_loopback: u8,
    },
}

/// Build a PSEC spec (`file_identifier "PSEC"`, schema v1.0).
pub(crate) fn psec_spec(
    ro: &[String],
    rw: &[String],
    deny: &[String],
    net: &NetSpec,
    ident: bool,
) -> Vec<u8> {
    psec_spec_minor(ro, rw, deny, net, ident, 0)
}

/// `psec_spec` with a selectable schema minor version.
#[allow(dead_code)]
pub(crate) fn psec_spec_minor(
    ro: &[String],
    rw: &[String],
    deny: &[String],
    net: &NetSpec,
    ident: bool,
    minor: u16,
) -> Vec<u8> {
    psec_spec_full(
        ro,
        rw,
        deny,
        &[],
        net,
        &[],
        &[],
        None,
        None,
        ident,
        minor,
    )
}

/// Full-surface spec builder: fs grants + enumerate + egress allow
/// (with `except` subnets) + egress deny rules + capabilities string +
/// ingress policy. Each `deny_rules`/`excepts` entry is an
/// `(address, prefix)` subnet; rules carry a tcp port.
#[allow(dead_code)]
pub(crate) fn psec_spec_full(
    ro: &[String],
    rw: &[String],
    deny: &[String],
    enumerate: &[String],
    net: &NetSpec,
    excepts: &[(String, u8)],
    deny_rules: &[(String, u8, u16)],
    caps: Option<&str>,
    ingress: Option<(u8, u8)>,
    ident: bool,
    minor: u16,
) -> Vec<u8> {
    let mut fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(1, minor))];
    // capabilities is a single comma-joined string (slot 1). The OS
    // capability gate sits in front of egress rules: without
    // `internetClient` every connect is refused before rule matching.
    let caps = caps.map(str::to_string).or_else(|| {
        matches!(net, NetSpec::AllowOnly { .. } | NetSpec::AllowCidr { .. })
            .then(|| "internetClient".to_string())
    });
    if let Some(c) = caps {
        fields.push((1, FieldV::Ref(Box::new(SpecNode::Str(c)))));
    }
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
    if !matches!(net, NetSpec::None) || ingress.is_some() {
        fields.push((
            7,
            FieldV::Ref(Box::new(net_policy_node_full(
                net, excepts, deny_rules, ingress,
            ))),
        ));
    }
    if !enumerate.is_empty() {
        // fs_enumerate — slot 8 (v1.1 surface).
        fields.push((8, FieldV::Ref(Box::new(SpecNode::StrVec(enumerate.to_vec())))));
    }
    let root = SpecNode::Table {
        max_slot: 8,
        fields,
    };
    fb_finish(Fb::new(ident), &root)
}

/// Egress rule pieces shared by the simple `NetSpec` path and the
/// full-surface builder. Returns the `EndpointRule` for a
/// destination+port pair (with optional `except` subnets).
fn endpoint_rule_node(
    addr: &str,
    prefix: u8,
    port: u16,
    end_port: u16,
    excepts: &[(String, u8)],
) -> SpecNode {
    // IpSubnet{ address, prefix_length }
    let subnet = SpecNode::Table {
        max_slot: 1,
        fields: vec![
            (0, FieldV::Ref(Box::new(SpecNode::Str(addr.to_string())))),
            (1, FieldV::U8(prefix)),
        ],
    };
    // DestinationRule{ subnet, except? }
    let mut dest_fields: Vec<(usize, FieldV)> = vec![(0, FieldV::Ref(Box::new(subnet)))];
    if !excepts.is_empty() {
        let xs: Vec<SpecNode> = excepts
            .iter()
            .map(|(a, p)| SpecNode::Table {
                max_slot: 1,
                fields: vec![
                    (0, FieldV::Ref(Box::new(SpecNode::Str(a.clone())))),
                    (1, FieldV::U8(*p)),
                ],
            })
            .collect();
        dest_fields.push((1, FieldV::Ref(Box::new(SpecNode::TabVec(xs)))));
    }
    let dest = SpecNode::Table {
        max_slot: 1,
        fields: dest_fields,
    };
    // PortRule{ protocol: tcp(1), port, end_port? }
    let mut pr_fields: Vec<(usize, FieldV)> =
        vec![(0, FieldV::U8(1)), (1, FieldV::U16(port))];
    if end_port != 0 {
        pr_fields.push((2, FieldV::U16(end_port)));
    }
    let port_rule = SpecNode::Table {
        max_slot: 2,
        fields: pr_fields,
    };
    // EndpointRule{ destinations: [..], ports: [..] }
    SpecNode::Table {
        max_slot: 1,
        fields: vec![
            (0, FieldV::Ref(Box::new(SpecNode::TabVec(vec![dest])))),
            (1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![port_rule])))),
        ],
    }
}

fn net_policy_node_full(
    spec: &NetSpec,
    excepts: &[(String, u8)],
    deny_rules: &[(String, u8, u16)],
    ingress: Option<(u8, u8)>,
) -> SpecNode {
    let mut egress_fields: Vec<(usize, FieldV)> = vec![(0, FieldV::U8(0))];
    let (addr, prefix, port, end_port) = match spec {
        NetSpec::AllowOnly { addr, port } => (addr.clone(), 32u8, *port, 0u16),
        NetSpec::AllowCidr {
            addr,
            prefix,
            port,
            end_port,
        } => (addr.clone(), *prefix, *port, *end_port),
        _ => (String::new(), 0u8, 0u16, 0u16),
    };
    if !addr.is_empty() {
        let rule = endpoint_rule_node(&addr, prefix, port, end_port, excepts);
        egress_fields.push((1, FieldV::Ref(Box::new(SpecNode::TabVec(vec![rule])))));
    }
    if !deny_rules.is_empty() {
        let rules: Vec<SpecNode> = deny_rules
            .iter()
            .map(|(a, p, pt)| endpoint_rule_node(a, *p, *pt, 0, &[]))
            .collect();
        // EndpointPolicy.deny — vtable slot 2.
        egress_fields.push((2, FieldV::Ref(Box::new(SpecNode::TabVec(rules)))));
    }
    let egress = SpecNode::Table {
        max_slot: 2,
        fields: egress_fields,
    };
    let mut net_fields: Vec<(usize, FieldV)> = vec![(1, FieldV::Ref(Box::new(egress)))];
    let ingress = ingress.or(match spec {
        NetSpec::DenyAllIngress {
            default_action,
            host_loopback,
        } => Some((*default_action, *host_loopback)),
        _ => None,
    });
    if let Some((default_action, host_loopback)) = ingress {
        // IngressPolicy{ default_action, host_loopback }
        let ing = SpecNode::Table {
            max_slot: 1,
            fields: vec![(0, FieldV::U8(default_action)), (1, FieldV::U8(host_loopback))],
        };
        // NetworkPolicy slot 3 = ingress.
        net_fields.push((3, FieldV::Ref(Box::new(ing))));
    }
    SpecNode::Table {
        max_slot: 3,
        fields: net_fields,
    }
}

/// v1.1-era surface variants for the create/close ladder — fields the
/// shipped encoder deliberately omits. Returns (label, spec) pairs.
#[allow(dead_code)]
pub(crate) fn psec_spec_v11_extras() -> Vec<(&'static str, Vec<u8>)> {
    fn root(fields: Vec<(usize, FieldV)>) -> Vec<u8> {
        let mut f: Vec<(usize, FieldV)> = vec![(0, FieldV::Ver(1, 1))];
        f.extend(fields);
        fb_finish(
            Fb::new(true),
            &SpecNode::Table {
                max_slot: 8,
                fields: f,
            },
        )
    }
    let deny_egress = || SpecNode::Table {
        max_slot: 2,
        fields: vec![(0, FieldV::U8(0))],
    };
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    // allowed_appcontainer_peer — NetworkPolicy slot 2 (string).
    {
        let net = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (1, FieldV::Ref(Box::new(deny_egress()))),
                (
                    2,
                    FieldV::Ref(Box::new(SpecNode::Str("MyPeer-Profile".into()))),
                ),
            ],
        };
        out.push(("peer", root(vec![(7, FieldV::Ref(Box::new(net)))])));
    }
    // proxy — NetworkPolicy slot 0: ProxyInfo{ url }.
    {
        let proxy_info = SpecNode::Table {
            max_slot: 0,
            fields: vec![(
                0,
                FieldV::Ref(Box::new(SpecNode::Str(
                    "http://127.0.0.1:8080".into(),
                ))),
            )],
        };
        let net = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (0, FieldV::Ref(Box::new(proxy_info))),
                (1, FieldV::Ref(Box::new(deny_egress()))),
            ],
        };
        out.push(("proxy", root(vec![(7, FieldV::Ref(Box::new(net)))])));
        // proxy + host_loopback exemption — a proxy endpoint is
        // host-local; the parser may require the pair.
        let ingress = SpecNode::Table {
            max_slot: 1,
            fields: vec![(0, FieldV::U8(0)), (1, FieldV::U8(1))],
        };
        let net2 = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (0, FieldV::Ref(Box::new(proxy_info2()))),
                (1, FieldV::Ref(Box::new(deny_egress()))),
                (3, FieldV::Ref(Box::new(ingress))),
            ],
        };
        out.push(("proxy+hostlb", root(vec![(7, FieldV::Ref(Box::new(net2)))])));
        // proxy + MXC-Loopback peer — the SDK's declared-peer shape.
        let net3 = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (0, FieldV::Ref(Box::new(proxy_info2()))),
                (1, FieldV::Ref(Box::new(deny_egress()))),
                (
                    2,
                    FieldV::Ref(Box::new(SpecNode::Str("MXC-Loopback".into()))),
                ),
            ],
        };
        out.push(("proxy+peer", root(vec![(7, FieldV::Ref(Box::new(net3)))])));
        // proxy with NO egress field — the SDK treats proxy and direct
        // egress as mutually exclusive forms (egress absent, not
        // deny-by-default).
        let net4 = SpecNode::Table {
            max_slot: 3,
            fields: vec![(0, FieldV::Ref(Box::new(proxy_info2())))],
        };
        out.push(("proxy-noegress", root(vec![(7, FieldV::Ref(Box::new(net4)))])));
        let net5 = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (0, FieldV::Ref(Box::new(proxy_info2()))),
                (
                    3,
                    FieldV::Ref(Box::new(SpecNode::Table {
                        max_slot: 1,
                        fields: vec![(0, FieldV::U8(0)), (1, FieldV::U8(1))],
                    })),
                ),
            ],
        };
        out.push(("proxy-noegress+lb", root(vec![(7, FieldV::Ref(Box::new(net5)))])));
        // maximal: proxy + peer + hostlb + multi-caps at root.
        let net6 = SpecNode::Table {
            max_slot: 3,
            fields: vec![
                (0, FieldV::Ref(Box::new(proxy_info2()))),
                (
                    2,
                    FieldV::Ref(Box::new(SpecNode::Str("MXC-Loopback".into()))),
                ),
                (
                    3,
                    FieldV::Ref(Box::new(SpecNode::Table {
                        max_slot: 1,
                        fields: vec![(0, FieldV::U8(0)), (1, FieldV::U8(1))],
                    })),
                ),
            ],
        };
        out.push((
            "proxy-full",
            {
                let mut f: Vec<(usize, FieldV)> = vec![
                    (0, FieldV::Ver(1, 1)),
                    (
                        1,
                        FieldV::Ref(Box::new(SpecNode::Str(
                            "internetClient,networkLoopback".into(),
                        ))),
                    ),
                    (7, FieldV::Ref(Box::new(net6))),
                ];
                let r = SpecNode::Table {
                    max_slot: 8,
                    fields: std::mem::take(&mut f),
                };
                fb_finish(Fb::new(true), &r)
            },
        ));
        fn proxy_info2() -> SpecNode {
            SpecNode::Table {
                max_slot: 0,
                fields: vec![(
                    0,
                    FieldV::Ref(Box::new(SpecNode::Str(
                        "http://127.0.0.1:8080".into(),
                    ))),
                )],
            }
        }
    }
    // ui_restrictions — root slot 3 (u64 mask).
    out.push(("ui-restrictions", root(vec![(3, FieldV::U64(0x1f))])));
    // disallow_win32k_system_calls — root slot 2 (u8/bool).
    out.push(("disallow-win32k", root(vec![(2, FieldV::U8(1))])));
    // capabilities — comma-joined multi-capability string.
    out.push((
        "caps-multi",
        root(vec![(
            1,
            FieldV::Ref(Box::new(SpecNode::Str(
                "internetClient,privateNetworkClientServer,networkLoopback".into(),
            ))),
        )]),
    ));
    // fs_enumerate — root slot 8 (string vector).
    {
        let paths = SpecNode::StrVec(vec!["C:\\scratch".into()]);
        out.push((
            "fs-enumerate",
            root(vec![(8, FieldV::Ref(Box::new(paths)))]),
        ));
    }
    // except subnet inside an allow DestinationRule (slot 1).
    out.push((
        "net-allow-except",
        psec_spec_full(
            &[],
            &[],
            &[],
            &[],
            &NetSpec::AllowCidr {
                addr: "10.20.30.0".into(),
                prefix: 24,
                port: 443,
                end_port: 0,
            },
            &[("10.20.30.40".into(), 32)],
            &[],
            Some("internetClient"),
            None,
            true,
            1,
        ),
    ));
    // egress deny endpoint rule (EndpointPolicy slot 2).
    out.push((
        "net-deny-rule",
        psec_spec_full(
            &[],
            &[],
            &[],
            &[],
            &NetSpec::DenyAll,
            &[],
            &[("10.20.30.40".into(), 32, 443)],
            Some("internetClient"),
            None,
            true,
            1,
        ),
    ));
    out
}

/// Bare-bones spec: version only (+ optional ident).
pub(crate) fn psec_spec_minimal(ident: bool, minor: u16) -> Vec<u8> {
    let root = SpecNode::Table {
        max_slot: 8,
        fields: vec![(0, FieldV::Ver(1, minor))],
    };
    fb_finish(Fb::new(ident), &root)
}
