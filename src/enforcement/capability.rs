//! The machine-readable capability catalog — one row per sandbox
//! mechanism and per isolation boundary, plus the shared requirement
//! vocabulary the capability probes, `--report` outputs, and (PR-16)
//! mechanism selection all read from.
//!
//! This module is the single source for data that must not diverge:
//!
//! - the per-layer egress disposition `plan` and the PoC `--report`
//!   outputs emit IS the catalog row's [`LayerCapability`] — the
//!   `os`/`note` strings are copied into [`EgressLayerStatus`] here,
//!   not re-typed at each call site;
//! - a mechanism's `requires` ids are the same tokens a probe names in
//!   [`UnmetRequirement::requirements`] and a `--report` `missing`
//!   member lists — a report can never claim requirements the catalog
//!   does not name;
//! - `status`/`deficiencies` bound the claim honestly — a verified
//!   environment is evidence scope, never a general-support statement,
//!   and an unsupported combination refuses or reports `null` instead
//!   of inferring a different path.
//!
//! The committed `docs/capability-matrix.json` is
//! [`capability_matrix_json`] output; `tests/capability_matrix.rs`
//! diffs the two so the document can never drift from the
//! implementation. This is leaf data (layer 0) — mechanism facts are
//! static strings, target facts come from [`crate::execution`].

use crate::enforcement::EgressLayerStatus;
use crate::execution::{
    ExecutionSubstrate, ExecutionTarget, IsolationKind, TargetOs, WindowsNativeMechanism,
};

/// Schema version of the [`capability_matrix_json`] document.
pub const CAPABILITY_MATRIX_SCHEMA_VERSION: &str = "1";

/// A host/kernel capability a mechanism requires — or uses when
/// present. `id` is the stable token naming the requirement wherever a
/// report or selector speaks of it; `detail` is what the launch needs
/// it for.
///
/// Only ids a launch-time probe actually measures carry the `missing`
/// contract — unotify/ebpf's `check_support` ([`UnmetRequirement`]) and
/// namespaced's `ProbeReport::missing()` emit exactly those tokens. The
/// rest name requirements checked at policy/spawn/init time (e.g.
/// `no-new-privs`, `x86-64`) — an unmet one refuses the launch
/// through its own error path, never through a `missing` member.
#[derive(Debug)]
pub struct Requirement {
    pub id: &'static str,
    pub detail: &'static str,
}

/// The OS-level disposition of one egress layer under a mechanism.
///
/// `os` names the OS mechanism that evaluates this layer — a partial
/// one counts (Landlock netport rules bind a TCP connect port but no
/// destination; the SBPL profile binds loopback `host:port` only).
/// `os` is `None` only when no mechanism on the path can reach the
/// layer at all — it then stays at the RPC/Auditor surface,
/// `granularity`/`transports` are empty, and `note` says why honestly.
/// `granularity` names the destination forms the OS mechanism
/// evaluates (`"fqdn"`, `"cidr"`, `"literal-ip"`, `"port"`, `"proto"`);
/// `transports` the traffic it covers (`"tcp"`, `"udp"`, `"dns"`,
/// `"any"` for a transport-independent destination rule).
#[derive(Debug)]
pub struct LayerCapability {
    /// `name` (FQDN rules) or `ip` (CIDR / literal-IP rules).
    pub layer: &'static str,
    /// The OS mechanism evaluating this layer (possibly partially —
    /// `granularity` scopes its reach); `None` = RPC-only.
    pub os: Option<&'static str>,
    /// Destination forms the OS mechanism enforces at this layer.
    pub granularity: &'static [&'static str],
    /// Transports the OS mechanism covers at this layer.
    pub transports: &'static [&'static str],
    /// Why the layer is — or is not — covered. The same text
    /// [`EgressLayerStatus::note`] carries in `plan`/`--report` output.
    pub note: &'static str,
}

impl LayerCapability {
    /// The [`EgressLayerStatus`] this capability projects — the RPC
    /// surface is the Auditor's argument checks on every path.
    pub fn status(&self) -> EgressLayerStatus {
        EgressLayerStatus {
            layer: self.layer,
            rpc: "auditor",
            os: self.os.map(|s| s.to_string()),
            note: Some(self.note.to_string()),
        }
    }
}

/// One sandbox mechanism's capability row.
///
/// `status` vocabulary: `adopted` (product path), `adopted-conditional`
/// (adopted behind a per-launch capability probe — failure refuses),
/// `opt-in` (implemented alternative path, explicit selection only),
/// `poc` (proof-of-concept, not a product route), `none` (no
/// mechanism). `auto_candidate` marks the rows the PR-16 `auto` Linux
/// egress-selection may pick; every mechanism today still requires its
/// explicit selection surface (`selected_by`).
#[derive(Debug)]
pub struct MechanismCapability {
    /// Stable row id — one id under two member spellings, kept for the
    /// existing schemas: `target.sandbox_mechanism` in `plan`/launch
    /// reports, `capability.capability_id` in the PoC `--report`
    /// payloads.
    pub id: &'static str,
    /// The workload OS the mechanism applies to.
    pub os: &'static str,
    /// The CLI surface that selects it (`run`, `unotify-run`,
    /// `--windows-mechanism psec`, ...).
    pub selected_by: &'static str,
    /// Adoption status — see the type-level vocabulary.
    pub status: &'static str,
    /// Whether the design's `auto` Linux egress-selection may pick it.
    pub auto_candidate: bool,
    /// `os.*` control ids this mechanism's `plan` emits.
    pub controls: &'static [&'static str],
    /// The `name` + `ip` egress-layer dispositions (index 0 = name).
    pub layers: [LayerCapability; 2],
    /// Egress transports OS enforcement reaches at all on this path.
    pub transports: &'static [&'static str],
    /// Required host capabilities — a missing one refuses the launch.
    pub requires: &'static [Requirement],
    /// Used when present; absence degrades honestly and is recorded.
    pub optional: &'static [Requirement],
    /// Named gaps the mechanism cannot enforce.
    pub deficiencies: &'static [&'static str],
    /// When a launch selects this mechanism.
    pub select: &'static str,
    /// Conditions that refuse the launch — never a silent fallback.
    pub refuse: &'static [&'static str],
}

impl MechanismCapability {
    /// The `(name, ip)` layer statuses — what the mechanism's
    /// `os_egress_layer_status` and `--report` emit.
    pub fn egress_status(&self) -> (EgressLayerStatus, EgressLayerStatus) {
        (self.layers[0].status(), self.layers[1].status())
    }

    /// The single-layer status (`"name"` or `"ip"`).
    pub fn layer_status(&self, layer: &str) -> EgressLayerStatus {
        self.layers
            .iter()
            .find(|l| l.layer == layer)
            .expect("egress layer is 'name' or 'ip'")
            .status()
    }
}

/// An `--isolation` boundary — the coarser execution substrate the
/// mechanism rows do not cover. `kind` is the typed
/// [`IsolationKind`]; `unit`/`guest_os`/`substrate` serialize from its
/// methods so the matrix reports exactly what the launch would record.
#[derive(Debug)]
pub struct BoundaryCapability {
    pub kind: IsolationKind,
    /// The host environments the boundary exists on — a launch off
    /// them refuses at selection/`plan` time.
    pub host: &'static str,
    /// The engines (`--engine`) that can drive it.
    pub engines: &'static [&'static str],
    /// Same status vocabulary as [`MechanismCapability::status`].
    pub status: &'static str,
    /// Prerequisites and honest scope.
    pub note: &'static str,
}

/// An OS-independent control — the launch + RPC surface every
/// mechanism row shares.
#[derive(Debug)]
pub struct CommonControl {
    pub id: &'static str,
    /// `launch` or `rpc`.
    pub layer: &'static str,
    pub mechanism: &'static str,
    pub note: &'static str,
}

/// One probe-verified set of unmet requirements — the shared currency
/// between a `check_support` probe, a `--report` `missing` member, and
/// a mechanism selector that refuses rather than falls back.
/// `requirements` holds [`Requirement::id`] tokens from the
/// mechanism's catalog `requires`; `detail` is the human-readable
/// diagnostic.
#[derive(Debug)]
pub struct UnmetRequirement {
    pub requirements: Vec<&'static str>,
    pub detail: String,
}

impl UnmetRequirement {
    /// A single unmet requirement.
    pub fn one(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            requirements: vec![id],
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for UnmetRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for UnmetRequirement {}

mod matrix;
pub use matrix::*;

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// The catalog row with `id`, when one exists.
pub fn mechanism(id: &str) -> Option<&'static MechanismCapability> {
    MECHANISMS.iter().find(|m| m.id == id)
}

/// The mechanism a recorded [`ExecutionTarget`] implies.
///
/// Only a *native* substrate has a mechanism on this host — for
/// container/VM targets the enforcement lives inside the guest and the
/// guest's own report names it (`None` here, never an inference). On a
/// native Windows target the effective `--windows-mechanism` picks the
/// row.
pub fn mechanism_for(target: &ExecutionTarget) -> Option<&'static MechanismCapability> {
    if target.substrate != ExecutionSubstrate::Native {
        return None;
    }
    Some(match target.workload_os {
        TargetOs::Linux => match target.native_linux_mechanism {
            Some(crate::execution::LinuxNativeMechanism::Namespaced) => &LINUX_NAMESPACED,
            Some(crate::execution::LinuxNativeMechanism::Native) => &LINUX_NATIVE,
            // A refused selection binds no mechanism — reporting the
            // native row would claim a mechanism that never ran. An
            // unselected target keeps the legacy default.
            None if target.linux_selection_refused => return None,
            None => &LINUX_NATIVE,
        },
        TargetOs::MacOs => &MACOS_SBPL,
        TargetOs::Windows => match target.effective_windows_mechanism() {
            Some(WindowsNativeMechanism::Psec) => &WINDOWS_PSEC,
            _ => &WINDOWS_APPCONTAINER,
        },
        TargetOs::Other(_) => &GENERIC_NONE,
    })
}

// ---------------------------------------------------------------------------
// Matrix serialization
// ---------------------------------------------------------------------------

struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

fn write_requirement(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    r: &Requirement,
) -> std::fmt::Result {
    f.member("id", r.id)?;
    f.member("detail", r.detail)
}

fn write_layer(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    l: &LayerCapability,
) -> std::fmt::Result {
    f.member("layer", l.layer)?;
    match l.os {
        Some(os) => f.member("os", os)?,
        None => f.member("os", JsonNull)?,
    }
    f.member(
        "granularity",
        nojson::array(|a| {
            for g in l.granularity {
                a.element(*g)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "transports",
        nojson::array(|a| {
            for t in l.transports {
                a.element(*t)?;
            }
            Ok(())
        }),
    )?;
    f.member("note", l.note)
}

fn write_mechanism(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    m: &MechanismCapability,
) -> std::fmt::Result {
    f.member("id", m.id)?;
    f.member("os", m.os)?;
    f.member("selected_by", m.selected_by)?;
    f.member("status", m.status)?;
    f.member("auto_candidate", m.auto_candidate)?;
    f.member(
        "controls",
        nojson::array(|a| {
            for c in m.controls {
                a.element(*c)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "layers",
        nojson::array(|a| {
            for l in &m.layers {
                a.element(nojson::object(|lo| write_layer(lo, l)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "transports",
        nojson::array(|a| {
            for t in m.transports {
                a.element(*t)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "requires",
        nojson::array(|a| {
            for r in m.requires {
                a.element(nojson::object(|ro| write_requirement(ro, r)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "optional",
        nojson::array(|a| {
            for r in m.optional {
                a.element(nojson::object(|ro| write_requirement(ro, r)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "deficiencies",
        nojson::array(|a| {
            for d in m.deficiencies {
                a.element(*d)?;
            }
            Ok(())
        }),
    )?;
    f.member("select", m.select)?;
    f.member(
        "refuse",
        nojson::array(|a| {
            for r in m.refuse {
                a.element(*r)?;
            }
            Ok(())
        }),
    )
}

fn write_boundary(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    b: &BoundaryCapability,
) -> std::fmt::Result {
    f.member("id", b.kind.name())?;
    f.member("substrate", b.kind.substrate().name())?;
    f.member("unit", b.kind.unit().name())?;
    f.member("guest_os", b.kind.guest_os().name())?;
    f.member("host", b.host)?;
    f.member(
        "engines",
        nojson::array(|a| {
            for e in b.engines {
                a.element(*e)?;
            }
            Ok(())
        }),
    )?;
    f.member("status", b.status)?;
    f.member("note", b.note)
}

fn write_common_control(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    c: &CommonControl,
) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("layer", c.layer)?;
    f.member("mechanism", c.mechanism)?;
    f.member("note", c.note)
}

/// Serialize the catalog as the versioned matrix document — the output
/// `mcp-writ capability-matrix` prints and `docs/capability-matrix.json`
/// commits. Pure function of the catalog: no host probing, so the
/// document describes the product, never this machine.
pub fn capability_matrix_json() -> String {
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", CAPABILITY_MATRIX_SCHEMA_VERSION)?;
        o.member("component", "mcp-writ")?;
        o.member("generated_from", "enforcement-model")?;
        o.member(
            "positioning",
            nojson::object(|p| -> std::fmt::Result {
                p.member(
                    "native_warden",
                    "linux-first — Landlock+seccomp+no_new_privs on Linux; \
                     sandbox-exec (a deprecated, legacy mechanism) on macOS; \
                     AppContainer or the conditional PSEC on Windows",
                )?;
                p.member(
                    "stronger_boundaries",
                    "for workloads that need a container or VM boundary rather \
                     than a native-process sandbox, use --isolation (kata, \
                     apple-container, hyperv, windows-sandbox) or an OCI \
                     container (--engine docker|podman|wslc)",
                )?;
                p.member(
                    "honesty",
                    "an unsupported combination refuses or reports null — the \
                     matrix never infers enforcement from a different path, \
                     and `verified environment` bounds evidence scope, not \
                     general support",
                )
            }),
        )?;
        o.member(
            "common_controls",
            nojson::array(|a| {
                for c in COMMON_CONTROLS {
                    a.element(nojson::object(|co| write_common_control(co, c)))?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "mechanisms",
            nojson::array(|a| {
                for m in MECHANISMS {
                    a.element(nojson::object(|mo| write_mechanism(mo, m)))?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "boundaries",
            nojson::array(|a| {
                for b in BOUNDARIES {
                    a.element(nojson::object(|bo| write_boundary(bo, b)))?;
                }
                Ok(())
            }),
        )
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_layers_named() {
        let mut ids = std::collections::HashSet::new();
        for m in MECHANISMS {
            assert!(ids.insert(m.id), "duplicate mechanism id {}", m.id);
            assert_eq!(m.layers[0].layer, "name");
            assert_eq!(m.layers[1].layer, "ip");
            for c in m.controls {
                assert!(c.starts_with("os."), "{} not an os.* id", c);
            }
            for r in m.requires.iter().chain(m.optional.iter()) {
                assert!(!r.id.is_empty());
                assert!(!r.detail.is_empty());
            }
        }
    }

    #[test]
    fn every_isolation_kind_has_a_boundary_row() {
        for kind in [
            IsolationKind::Container,
            IsolationKind::Kata,
            IsolationKind::AppleContainer,
            IsolationKind::HyperV,
            IsolationKind::WindowsSandbox,
        ] {
            assert!(
                BOUNDARIES.iter().any(|b| b.kind == kind),
                "no boundary row for {}",
                kind.name()
            );
        }
    }

    #[test]
    fn matrix_json_parses() {
        let body = capability_matrix_json();
        let leaked: &'static str = Box::leak(body.clone().into_boxed_str());
        nojson::RawJson::parse(leaked).expect("matrix must be valid JSON");
    }
}
