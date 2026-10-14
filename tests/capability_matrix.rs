//! PR-13: the machine-readable capability matrix.
//!
//! - `mcp-writ capability-matrix` emits the catalog as one JSON object
//!   on stdout — the same document `docs/capability-matrix.json`
//!   commits, so implementation and checked-in doc can never drift.
//! - The catalog is the single source for the strings `plan` and the
//!   PoC `--report` outputs emit: a mechanism's `egress` projection is
//!   literally what `os_egress_layer_status` returns, and the
//!   `requires` ids are the tokens probes/report `missing` members
//!   name.
//! - Honesty invariants: an `os: null` layer is never silently
//!   substituted — its note must attribute the enforcement to the
//!   Auditor surface; `status` uses only the documented vocabulary; a
//!   non-native substrate has no host-side mechanism to name.

use std::process::{Command, Stdio};

use mcp_writ::enforcement::{capability, mechanism_for};
use mcp_writ::execution::{ExecutionSubstrate, ExecutionTarget, TargetOs, WindowsNativeMechanism};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

fn parse(body: String) -> nojson::RawJson<'static> {
    nojson::RawJson::parse(Box::leak(body.into_boxed_str())).expect("matrix must be valid JSON")
}

fn matrix_json() -> nojson::RawJson<'static> {
    parse(mcp_writ::enforcement::capability_matrix_json())
}

#[test]
fn capability_matrix_cli_emits_the_catalog() {
    let out = Command::new(bin())
        .arg("capability-matrix")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run mcp-writ capability-matrix");
    assert!(
        out.status.success(),
        "capability-matrix must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8(out.stdout).expect("stdout utf8");
    let json = parse(body.trim().to_string());
    let v = json.value();
    assert_eq!(
        v.to_member("schema_version")
            .and_then(|m| m.required())
            .unwrap()
            .as_string_str()
            .unwrap(),
        mcp_writ::enforcement::CAPABILITY_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(
        v.to_member("component")
            .and_then(|m| m.required())
            .unwrap()
            .as_string_str()
            .unwrap(),
        "mcp-writ"
    );
    let mechanisms = v
        .to_member("mechanisms")
        .and_then(|m| m.required())
        .unwrap()
        .to_array()
        .unwrap();
    assert_eq!(
        mechanisms.count(),
        capability::MECHANISMS.len(),
        "CLI output must carry every catalog row"
    );
}

#[test]
fn committed_doc_matches_generated() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/capability-matrix.json");
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "docs/capability-matrix.json must be committed \
             (`mcp-writ capability-matrix > docs/capability-matrix.json`): {e}"
        )
    });
    assert!(
        !doc.starts_with('\u{FEFF}') && !doc.contains('\r'),
        "capability-matrix.json: UTF-8 without BOM, LF line endings"
    );
    let generated = mcp_writ::enforcement::capability_matrix_json();
    assert_eq!(
        doc.trim_end(),
        generated.trim_end(),
        "docs/capability-matrix.json drifted from enforcement::capability — \
         regenerate with `mcp-writ capability-matrix`"
    );
}

#[test]
fn mechanism_rows_carry_stable_shape() {
    const STATUSES: &[&str] = &["adopted", "adopted-conditional", "opt-in", "poc", "none"];
    let json = matrix_json();
    let mechanisms = json
        .value()
        .to_member("mechanisms")
        .and_then(|m| m.required())
        .unwrap()
        .to_array()
        .unwrap();
    let mut seen = std::collections::HashSet::new();
    for m in mechanisms {
        let id = m
            .to_member("id")
            .and_then(|x| x.required())
            .unwrap()
            .as_string_str()
            .unwrap();
        assert!(seen.insert(id.to_string()), "duplicate mechanism id {id}");
        assert!(
            capability::mechanism(id).is_some(),
            "matrix row {id} missing from MECHANISMS"
        );
        let status = m
            .to_member("status")
            .and_then(|x| x.required())
            .unwrap()
            .as_string_str()
            .unwrap();
        assert!(STATUSES.contains(&status), "{id}: unknown status {status}");
        for req in ["requires", "optional"] {
            let mut req_ids = std::collections::HashSet::new();
            for r in m
                .to_member(req)
                .and_then(|x| x.required())
                .unwrap()
                .to_array()
                .unwrap()
            {
                let rid = r
                    .to_member("id")
                    .and_then(|x| x.required())
                    .unwrap()
                    .as_string_str()
                    .unwrap();
                assert!(req_ids.insert(rid.to_string()), "{id}: dup {req} id {rid}");
                assert!(
                    !r.to_member("detail")
                        .and_then(|x| x.required())
                        .unwrap()
                        .as_string_str()
                        .unwrap()
                        .is_empty(),
                    "{id}: {req} {rid} must name what it is needed for"
                );
            }
        }
    }
}

#[test]
fn unenforced_layers_attribute_the_auditor() {
    // An `os: null` layer means no OS mechanism evaluates it — the note
    // must then say the enforcement stays at the RPC/Auditor surface,
    // never imply a silent kernel fallback, and no OS-evaluated
    // granularity/transports may be claimed. A partial OS mechanism
    // (e.g. Landlock netport rules binding a port but no destination)
    // must instead be *named* in `os`, with `granularity` scoping its
    // reach.
    for m in capability::MECHANISMS {
        for layer in &m.layers {
            if layer.os.is_none() {
                assert!(
                    layer.note.contains("Auditor"),
                    "{} {}: os:null layer must attribute enforcement to the Auditor",
                    m.id,
                    layer.layer
                );
                assert!(
                    layer.granularity.is_empty() && layer.transports.is_empty(),
                    "{} {}: os:null layer claims no OS-evaluated forms",
                    m.id,
                    layer.layer
                );
            }
            let status = layer.status();
            assert_eq!(status.layer, layer.layer);
            assert_eq!(status.rpc, "auditor");
            assert_eq!(status.os.as_deref(), layer.os);
        }
    }
}

#[test]
fn mechanism_for_covers_every_target() {
    let native = ExecutionTarget::native();
    match native.workload_os {
        TargetOs::Linux => assert_eq!(mechanism_for(&native).unwrap().id, "linux-native"),
        TargetOs::MacOs => assert_eq!(mechanism_for(&native).unwrap().id, "macos-sbpl"),
        TargetOs::Windows => {
            assert_eq!(mechanism_for(&native).unwrap().id, "windows-appcontainer");
            let psec = native.with_native_windows_mechanism(WindowsNativeMechanism::Psec);
            assert_eq!(mechanism_for(&psec).unwrap().id, "windows-psec");
        }
        TargetOs::Other(_) => {
            assert_eq!(mechanism_for(&native).unwrap().id, "generic-none")
        }
    }
    // A non-native substrate has no host mechanism to name — the
    // guest's own report carries it.
    let guest = ExecutionTarget::linux_container(None, None);
    assert_eq!(guest.substrate, ExecutionSubstrate::Container);
    assert!(
        mechanism_for(&guest).is_none(),
        "container targets never infer a host mechanism"
    );
}

#[test]
fn host_plan_layers_match_the_catalog_row() {
    // The plan's egress layer statuses must be the catalog row's own
    // strings — this is the drift check between the launch path and
    // the matrix.
    let mech = mechanism_for(&ExecutionTarget::native()).expect("native host has a row");
    let warden = mcp_writ::warden::Warden::new(mcp_writ::policy::Policy::default());
    let plan = warden.enforcement_plan(
        None,
        "true",
        &mcp_writ::warden::SpawnOptions::default(),
        None,
        false,
    );
    let layers = plan
        .egress_layers
        .as_ref()
        .expect("native plan carries egress layers");
    for expected in mech.layers.iter() {
        let actual = layers
            .layers
            .iter()
            .find(|l| l.layer == expected.layer)
            .unwrap_or_else(|| panic!("plan lacks layer {}", expected.layer));
        assert_eq!(
            actual.os.as_deref(),
            expected.os,
            "{} {}",
            mech.id,
            expected.layer
        );
        assert_eq!(actual.note.as_deref(), Some(expected.note));
        assert_eq!(actual.rpc, "auditor");
    }
}
