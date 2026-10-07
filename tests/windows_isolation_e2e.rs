//! PR-30 e2e: Windows 新隔離機構（Win32 app isolation / PSEC /
//! IsolationSession / MXC）と現行 AppContainer+LPAC+Job+DACL baseline の
//! 比較・実機検証。
//!
//! `tests/fixtures/windows_isolation/winiso_probe.rs` が全 probe を担う
//! 単一の std-only fixture で、`facts` / `contracts` / `attempts` /
//! `ac-run` / `psec-run` / `psec-spec-test` の各モードの JSON 出力が
//! 証跡（evidence）そのもの。本ファイルは二層で検証する:
//!
//! * **golden 層**（全ホストで実行）: `golden/` に収めた実機出力が
//!   fixture の JSON 契約を満たすこと、および試行結果の分類規則
//!   （denied / refused / filtered / unavailable …）と候補ごとの
//!   採否判定ルールが fail-closed であること。
//! * **live 層**（Windows + rustc のみ）: fixture を実コンパイルして
//!   全 leg を実行し、実機応答が契約を満たすことを確認する。
//!   `MCP_WRIT_REQUIRE_WINISO_TESTS=1` の検証ジョブでは skip ではなく
//!   fail になる。
//!
//! PR-31 で製品経路（`mcp-writ run --windows-mechanism`）が接続され、
//! PR-32 でその経路自体を検証する product レグ（`winiso_live_product_run`）
//! が live 層に加わった — `run` の launch report が記録する機構名・
//! `os.process` observation・`result` が契約である。

use std::path::PathBuf;

#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use std::time::{Duration, Instant};

mod common;

const GOLDEN: &str = "tests/fixtures/windows_isolation/golden";

// ─── golden helpers ─────────────────────────────────────────────────────────

fn golden(name: &str) -> nojson::RawJson<'static> {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(GOLDEN)
            .join(name),
    )
    .unwrap_or_else(|e| panic!("golden {name}: {e}"));
    nojson::RawJson::parse(Box::leak(text.into_boxed_str()))
        .unwrap_or_else(|e| panic!("golden {name} must parse as JSON: {e}"))
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> Option<nojson::RawJsonValue<'j, 'j>> {
    v.to_member(key).ok()?.optional()
}

fn req_member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> nojson::RawJsonValue<'j, 'j> {
    member(v, key).unwrap_or_else(|| panic!("member '{key}' must exist"))
}

fn s(v: nojson::RawJsonValue<'_, '_>) -> String {
    v.to_unquoted_string_str()
        .unwrap_or_else(|e| panic!("string member: {e}"))
        .into_owned()
}

fn b(v: nojson::RawJsonValue<'_, '_>) -> bool {
    v.as_boolean_str()
        .unwrap_or_else(|e| panic!("bool member: {e}"))
        == "true"
}

fn num(v: nojson::RawJsonValue<'_, '_>) -> Option<u64> {
    v.as_integer_str().ok()?.parse().ok()
}

/// The evidence classification the comparison rests on — an op's raw
/// `result` token, mapped to what it *proves*. Anything unrecognized is
/// `Unverified`, never silently treated as a pass or a denial.
#[derive(Debug, PartialEq, Eq)]
enum Evidence {
    Ok,
    /// ERROR_ACCESS_DENIED / WSAEACCES — the boundary refused the op.
    Denied,
    /// ECONNREFUSED / WSAECONNREFUSED — the network stack answered; the
    /// sandbox did not block it (a refused connect is *not* a deny).
    Refused,
    /// No answer inside the bound — filtered / unreachable.
    Filtered,
    /// The leg did not run (input missing) — not evidence either way.
    Skipped,
    /// Any other error code or unrecognized token.
    Unverified,
}

fn classify(result: &str) -> Evidence {
    match result {
        "ok" => Evidence::Ok,
        "skipped" => Evidence::Skipped,
        "timeout" => Evidence::Filtered,
        "err:5" | "err:10013" => Evidence::Denied,
        "err:10061" => Evidence::Refused,
        _ => Evidence::Unverified,
    }
}

fn attempt_entry<'j>(
    json: nojson::RawJsonValue<'j, 'j>,
    op: &str,
) -> Option<nojson::RawJsonValue<'j, 'j>> {
    req_member(json, "attempts")
        .to_array()
        .unwrap()
        .find(|a| s(req_member(*a, "op")) == op)
}

fn attempt_evidence(json: nojson::RawJsonValue<'_, '_>, op: &str) -> Evidence {
    let Some(a) = attempt_entry(json, op) else {
        panic!("attempt '{op}' must be recorded");
    };
    classify(&s(req_member(a, "result")))
}

// ─── disposition rules ─────────────────────────────────────────────────────
//
// PR-30's job is a *bounded* judgment per candidate. The rules are
// deliberately fail-closed: a missing leg or an unverified tier lowers
// the verdict, never raises it. "adoptable" is reserved for mechanisms
// whose evidence clears every row AND whose contract is a supported
// public surface — no candidate earns that inside PR-30 alone.

#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    /// Current shipping mechanism — evidence baseline.
    Baseline,
    /// Works on the validated host but open conditions remain.
    Conditional,
    /// Cannot be judged on this host/contract — needs conditions met.
    Hold,
    /// Evidence shows it cannot meet the contract here.
    Rejected,
}

/// PSEC can never be "adoptable" on PR-30 evidence alone: the wire
/// contract is documented only through the MXC preview SDK and the OS
/// surface is unversioned across the servicing channel. Full enforcement
/// evidence on the host earns `Conditional`; anything less is `Hold`.
fn psec_disposition(
    contracts: Option<&nojson::RawJson>,
    spec_test: Option<&nojson::RawJson>,
    run: Option<&nojson::RawJson>,
) -> Disposition {
    let (Some(contracts), Some(spec_test), Some(run)) = (contracts, spec_test, run) else {
        return Disposition::Hold;
    };
    let Some(psec) = member(contracts.value(), "psec") else {
        return Disposition::Hold;
    };
    if !b(req_member(psec, "api_set")) {
        return Disposition::Hold;
    }
    // v1.x must be the supported contract on this host.
    let supported = req_member(psec, "version_support")
        .to_array()
        .unwrap()
        .find(|v| {
            member(*v, "major").and_then(num) == Some(1)
                && member(*v, "available").map(b) == Some(true)
        })
        .is_some();
    if !supported {
        return Disposition::Hold;
    }
    // The create ladder must have produced at least one v1.0 env.
    let ladder_ok = req_member(spec_test.value(), "attempts")
        .to_array()
        .unwrap()
        .any(|a| {
            s(req_member(a, "hr")) == "0x00000000"
                && b(req_member(a, "env_created"))
                && b(req_member(a, "closed"))
        });
    if !ladder_ok {
        return Disposition::Hold;
    }
    // The run must have enforced policy, not merely created an env.
    if s(req_member(run.value(), "create_hr")) != "0x00000000" {
        return Disposition::Hold;
    }
    if !b(req_member(run.value(), "env_closed")) || !b(req_member(run.value(), "spawn_ok")) {
        return Disposition::Hold;
    }
    let Some(child) = member(run.value(), "child") else {
        return Disposition::Hold;
    };
    if child.as_raw_str() == "null" {
        return Disposition::Hold;
    }
    let deny_legs = [
        "fs_write_ro",
        "fs_read_deny",
        "fs_write_deny",
        "fs_read_ungranted",
    ];
    let enforced = deny_legs.iter().all(|op| {
        attempt_entry(child, op)
            .map(|a| classify(&s(req_member(a, "result"))) == Evidence::Denied)
            .unwrap_or(false)
    });
    if !enforced {
        return Disposition::Hold;
    }
    // Positive controls: the granted legs must still pass. An env that
    // denied *everything* would satisfy `enforced` while proving
    // nothing about policy granularity — over-denial is a Hold too.
    let grants_ok = ["fs_read_ro", "fs_write_rw"].iter().all(|op| {
        attempt_entry(child, op)
            .map(|a| classify(&s(req_member(a, "result"))) == Evidence::Ok)
            .unwrap_or(false)
    });
    if !grants_ok {
        return Disposition::Hold;
    }
    // Egress deny must be a real policy refusal on both axes — port and
    // destination — not a dead host. A missing or non-Denied leg is a
    // Hold (insufficient evidence), never a soft pass.
    let net_denied = ["net_connect_deny", "net_connect_deny_dest"]
        .iter()
        .all(|op| {
            attempt_entry(child, op)
                .map(|a| classify(&s(req_member(a, "result"))) == Evidence::Denied)
                .unwrap_or(false)
        });
    if !net_denied {
        return Disposition::Hold;
    }
    Disposition::Conditional
}

/// IsolationSession is Insider/preview surface: no PR-30 leg exercises
/// the lifecycle/folder-sharing/stdin-stdio/cleanup rows, so the
/// verdict is a fixed Hold on every host — activation facts included.
/// Kept as a function rather than inlined so a future lab leg has the
/// one place where the verdict can lift.
fn isosession_disposition(contracts: Option<&nojson::RawJson>) -> Disposition {
    let _ = contracts;
    Disposition::Hold
}

/// The shipping mechanism: a clean run is the baseline everything else
/// is compared against; a failing baseline run is a regression, which
/// the comparison records as `Rejected` (evidence says the mechanism
/// did not meet the contract on this host — distinct from `Hold`).
fn ac_baseline_disposition(run: Option<&nojson::RawJson>) -> Disposition {
    let Some(run) = run else {
        return Disposition::Hold;
    };
    let Some(child) = member(run.value(), "child") else {
        return Disposition::Rejected;
    };
    if child.as_raw_str() == "null" {
        return Disposition::Rejected;
    }
    let enforced = [
        "fs_write_ro",
        "fs_read_deny",
        "fs_write_deny",
        "fs_read_ungranted",
    ]
    .iter()
    .all(|op| {
        attempt_entry(child, op)
            .map(|a| classify(&s(req_member(a, "result"))) == Evidence::Denied)
            .unwrap_or(false)
    });
    let cleanup = member(run.value(), "profile_deleted").map(b) == Some(true)
        && member(run.value(), "cleanup_error").map(b) == Some(false);
    if enforced && cleanup && b(req_member(run.value(), "spawn_ok")) {
        Disposition::Baseline
    } else {
        Disposition::Rejected
    }
}

/// Win32 app isolation needs the OS contract on the host *plus* the
/// packaging/consent path — PR-30 has no leg for the second half, so
/// the verdict is a fixed Hold on every host whether the API set is
/// implemented or not (presence alone is not enforcement evidence).
/// Same shape as `isosession_disposition`: one place to lift it once a
/// packaging leg exists.
fn appisolation_disposition(facts: Option<&nojson::RawJson>) -> Disposition {
    let _ = facts;
    Disposition::Hold
}

// ─── golden tests ───────────────────────────────────────────────────────────

#[test]
fn golden_facts_shape() {
    let json = golden("facts.json");
    assert_eq!(s(req_member(json.value(), "mode")), "facts");
    let host = req_member(json.value(), "host");
    for k in ["major", "minor", "build", "ubr"] {
        num(req_member(req_member(host, "os"), k)).unwrap();
    }
    assert!(s(req_member(host, "arch")).len() > 2);
    let token = req_member(json.value(), "token");
    assert!(b(req_member(token, "queried")));
    assert!(num(req_member(token, "integrity_level")).is_some());
    // File/service/API-set presence is recorded per name — never a bare
    // "feature present" claim.
    for list in ["files", "services", "api_sets"] {
        assert!(
            req_member(json.value(), list).to_array().unwrap().count() > 0,
            "{list} must record entries"
        );
    }
}

#[test]
fn golden_attempts_classification() {
    let json = golden("attempts-host.json");
    // On the unsandboxed host every leg must be Ok/Refused — any Denied
    // on the host itself would invalidate the sandbox-attribution of
    // every other leg.
    for a in req_member(json.value(), "attempts").to_array().unwrap() {
        let ev = classify(&s(req_member(a, "result")));
        match ev {
            Evidence::Denied => {
                // Host-level denies that are *expected* regardless of
                // sandboxing: HKLM is medium-IL-forbidden on a stock
                // non-elevated token.
                assert_eq!(
                    s(req_member(a, "op")),
                    "reg_write_hklm",
                    "unexpected host deny: {:?}",
                    a
                );
            }
            Evidence::Unverified => panic!("unverified host leg: {a:?}"),
            _ => {}
        }
    }
    assert!(member(json.value(), "env_seen").is_some());
    // env propagation is itself evidence (PSEC children do not inherit).
    assert_eq!(
        attempt_entry(json.value(), "fs_read_ro")
            .map(|a| s(req_member(a, "result")))
            .as_deref(),
        Some("ok")
    );
}

#[test]
fn golden_ac_run_baseline_invariants() {
    let json = golden("ac-run.json");
    assert_eq!(s(req_member(json.value(), "mode")), "ac-run");
    assert!(b(req_member(json.value(), "profile_created")));
    assert!(b(req_member(json.value(), "spawn_ok")));
    // Every grant must record apply AND restore — a grant without
    // restore is an ACL leak, not evidence.
    for g in req_member(json.value(), "grants").to_array().unwrap() {
        assert!(b(req_member(g, "applied")));
        assert!(b(req_member(g, "restored")));
    }
    assert!(b(req_member(json.value(), "profile_deleted")));
    assert!(!b(req_member(json.value(), "cleanup_error")));
    // Job-object kill-on-close: the grandchild must be observed dead.
    assert!(b(req_member(json.value(), "gc_killed")));

    let child = req_member(json.value(), "child");
    assert!(b(req_member(
        req_member(child, "context"),
        "is_appcontainer"
    )));
    for op in [
        "fs_write_ro",
        "fs_read_deny",
        "fs_write_deny",
        "fs_read_ungranted",
    ] {
        assert_eq!(attempt_evidence(child, op), Evidence::Denied, "{op}");
    }
    assert_eq!(attempt_evidence(child, "fs_read_ro"), Evidence::Ok);
    assert_eq!(attempt_evidence(child, "fs_write_rw"), Evidence::Ok);
    // AC env is inherited — unlike a security-environment child.
    let env_seen = req_member(child, "env_seen");
    assert!(
        env_seen
            .to_array()
            .unwrap()
            .any(|e| s(req_member(e, "name")) == "WINISO_RO_DIR" && b(req_member(e, "seen")))
    );
}

#[test]
fn golden_lpac_network_blocked_at_provider_init() {
    // LPAC denies Winsock provider init itself — distinct tier from
    // connect denial — and disallows spawning children entirely.
    let json = golden("ac-run-lpac.json");
    assert!(b(req_member(json.value(), "spawn_ok")));
    let child = req_member(json.value(), "child");
    assert_eq!(
        attempt_evidence(child, "net_wsastartup"),
        Evidence::Unverified
    );
    assert_eq!(
        attempt_evidence(child, "spawn_grandchild"),
        Evidence::Denied
    );
}

#[test]
fn golden_psec_run_enforcement_evidence() {
    let json = golden("psec-run.json");
    assert_eq!(s(req_member(json.value(), "mode")), "psec-run");
    assert!(b(req_member(json.value(), "spec_ok")));
    assert_eq!(s(req_member(json.value(), "create_hr")), "0x00000000");
    assert!(b(req_member(json.value(), "env_closed")));
    assert!(b(req_member(json.value(), "spawn_ok")));
    assert!(b(req_member(json.value(), "gc_killed")));

    let child = req_member(json.value(), "child");
    assert!(b(req_member(
        req_member(child, "context"),
        "is_appcontainer"
    )));
    for op in [
        "fs_write_ro",
        "fs_read_deny",
        "fs_write_deny",
        "fs_read_ungranted",
    ] {
        assert_eq!(attempt_evidence(child, op), Evidence::Denied, "{op}");
    }
    assert_eq!(attempt_evidence(child, "fs_read_ro"), Evidence::Ok);
    assert_eq!(attempt_evidence(child, "fs_write_rw"), Evidence::Ok);
    // Egress policy deny — WSAEACCES from the env, not a missing
    // listener (the AC baseline's answer is 10061).
    assert_eq!(
        attempt_evidence(child, "net_connect_deny"),
        Evidence::Denied
    );
    assert_eq!(
        attempt_evidence(child, "net_connect_deny_dest"),
        Evidence::Denied
    );
    // The allow-rule leg passing the egress filter but being dropped by
    // loopback isolation is `Filtered`, not Ok — recorded as observed.
    assert_eq!(
        attempt_evidence(child, "net_connect_allow"),
        Evidence::Filtered
    );
    // Security-environment children do NOT inherit the parent env block.
    let env_seen = req_member(child, "env_seen");
    for e in env_seen.to_array().unwrap() {
        assert!(
            !b(req_member(e, "seen")),
            "PSEC child must not see {}: env is not inherited",
            s(req_member(e, "name"))
        );
    }
    // Grandchild inside the env + job kill-on-close.
    assert_eq!(
        attempt_entry(child, "spawn_grandchild")
            .map(|a| s(req_member(a, "result")))
            .as_deref(),
        Some("ok")
    );
}

#[test]
fn golden_spec_ladder_hresults() {
    let json = golden("psec-spec-test.json");
    let rows: Vec<(String, String)> = req_member(json.value(), "attempts")
        .to_array()
        .unwrap()
        .map(|a| (s(req_member(a, "variant")), s(req_member(a, "hr"))))
        .collect();
    let hr_of = |name: &str| rows.iter().find(|(v, _)| v == name).map(|(_, h)| h.clone());
    assert_eq!(hr_of("minimal-ident-v1.0").as_deref(), Some("0x00000000"));
    // v1.1 unavailable is an important fact, not a failure.
    assert_eq!(hr_of("minimal-ident-v1.1").as_deref(), Some("0x80070032"));
    assert_eq!(hr_of("minimal-noident").as_deref(), Some("0x8007000d"));
    for name in [
        "deny-only",
        "ro-only",
        "rw-only",
        "net-only",
        "net-allow-rule",
        "fs-all-no-net",
        "deny-nested",
        "deny-cdrive",
        "full-ident",
    ] {
        assert_eq!(hr_of(name).as_deref(), Some("0x00000000"), "{name}");
    }
    // Every created env must be recorded closed.
    for a in req_member(json.value(), "attempts").to_array().unwrap() {
        if b(req_member(a, "env_created")) {
            assert!(
                b(req_member(a, "closed")),
                "env leak in {}",
                s(req_member(a, "variant"))
            );
        }
    }
}

#[test]
fn golden_disposition_rules_fail_closed() {
    let facts = golden("facts.json");
    let contracts = golden("contracts.json");
    let spec = golden("psec-spec-test.json");
    let run = golden("psec-run.json");

    // The captured host clears PSEC's evidence bar at Conditional —
    // never Adoptable (private contract, unversioned servicing).
    assert_eq!(
        psec_disposition(Some(&contracts), Some(&spec), Some(&run)),
        Disposition::Conditional
    );
    // Missing legs degrade, never promote.
    assert_eq!(
        psec_disposition(None, Some(&spec), Some(&run)),
        Disposition::Hold
    );
    assert_eq!(
        psec_disposition(Some(&contracts), None, Some(&run)),
        Disposition::Hold
    );
    // Activation-only IsolationSession is a Hold on every host.
    assert_eq!(isosession_disposition(Some(&contracts)), Disposition::Hold);
    // Win32 app isolation: the API set is not implemented on this host.
    assert_eq!(appisolation_disposition(Some(&facts)), Disposition::Hold);

    // The baseline judges as Baseline; a run without a child report or
    // without cleanup is Rejected — the tier never lies upward.
    assert_eq!(
        ac_baseline_disposition(Some(&golden("ac-run.json"))),
        Disposition::Baseline
    );
    let broken = nojson::RawJson::parse(Box::leak(
        "{\"mode\":\"ac-run\",\"profile_created\":true,\"spawn_ok\":true,\"child\":null,\"profile_deleted\":false,\"cleanup_error\":true}"
            .to_string()
            .into_boxed_str(),
    ))
    .unwrap();
    let broken: &'static _ = Box::leak(Box::new(broken));
    assert_eq!(ac_baseline_disposition(Some(broken)), Disposition::Rejected);
}

#[test]
fn disposition_degrades_on_unavailable_env() {
    // A psec-run that could not even create an env (exports missing or
    // create_hr unavailable) is Hold, not Conditional — and never a
    // crash on absent members.
    let weak = nojson::RawJson::parse(Box::leak(
        "{\"mode\":\"psec-run\",\"spec_len\":40,\"spec_ok\":true,\"create_hr\":\"unavailable\"}"
            .to_string()
            .into_boxed_str(),
    ))
    .unwrap();
    let weak: &'static _ = Box::leak(Box::new(weak));
    let contracts = golden("contracts.json");
    let spec = golden("psec-spec-test.json");
    assert_eq!(
        psec_disposition(Some(&contracts), Some(&spec), Some(weak)),
        Disposition::Hold
    );
}

/// The non-Windows guarantee: the live legs are `cfg!(windows)`-gated —
/// no winiso binary is ever spawned off Windows, and the golden layer
/// alone runs there.
#[cfg(not(windows))]
#[test]
fn non_windows_never_spawns_probe() {
    assert!(!cfg!(windows));
    assert!(compiled_probe().is_none());
}

#[cfg(not(windows))]
fn compiled_probe() -> Option<PathBuf> {
    None
}

// ─── live layer (Windows only) ──────────────────────────────────────────────

/// Compile the probe fixture once per test binary, next to cargo's own
/// scratch space — same `rustc -O` contract as the other fixtures.
#[cfg(windows)]
fn compiled_probe() -> Option<PathBuf> {
    static PROBE: OnceLock<Option<PathBuf>> = OnceLock::new();
    PROBE
        .get_or_init(|| {
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/windows_isolation/winiso_probe.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_winiso_build_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    common::skip_winiso_test(&format!("fixture build tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir.path().join("winiso_probe.exe");
            let status = std::process::Command::new("rustc")
                .args(["--edition", "2021", "-O", "-o"])
                .arg(&out)
                .arg(&src)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => Some(dir.keep().join("winiso_probe.exe")),
                Ok(s) => {
                    common::skip_winiso_test(&format!("rustc winiso_probe.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    common::skip_winiso_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

#[cfg(windows)]
fn evidence_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("MCP_WRIT_WINISO_EVIDENCE_DIR") {
        let d = PathBuf::from(d);
        std::fs::create_dir_all(&d).expect("create evidence dir");
        return d;
    }
    common::vm_test_root("MCP_WRIT_WINISO_TEST_ROOT", "winiso-e2e")
}

/// Mutable leg state (DACL-touched dirs, seeded files) belongs under the
/// run's work root — not inside `evidence_dir`, which holds only the
/// recorded leg JSON artifacts.
#[cfg(windows)]
fn work_dir(name: &str) -> PathBuf {
    common::vm_test_root("MCP_WRIT_WINISO_TEST_ROOT", "winiso-e2e").join(name)
}

/// Drain a child pipe on a reader thread so a bounded wait never
/// depends on the child's write timing — a blocking read() would sleep
/// past the bound. The buffer comes back over a channel so the drain is
/// boundable: join() could block on a pipe a surviving descendant still
/// holds.
#[cfg(windows)]
fn drain_pipe<R: std::io::Read + Send + 'static>(
    mut pipe: R,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tx.send(out);
    });
    rx
}

/// Terminate a spawned process *tree*: `Child::kill` reaches only the
/// direct child, but a wedged leg can leave the workload — or the
/// probe's sandboxed grandchild — running after the parent dies.
/// `taskkill /T /F` is the tree-kill the validate scripts already use;
/// `child.kill()` remains as the fallback if taskkill itself fails.
#[cfg(windows)]
fn kill_tree(child: &mut std::process::Child) {
    let _ = Command::new("taskkill.exe")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

/// Bounded run of a probe leg: piped stdout, 90s outer bound (the
/// fixture's internal waits are far tighter — this only covers a wedged
/// child), first stdout line returned as the leg JSON.
#[cfg(windows)]
fn run_leg(probe: &Path, args: &[&str], envs: &[(&str, String)]) -> String {
    let mut cmd = Command::new(probe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn winiso_probe");
    // stdout drains on a reader thread so the 90s bound holds even when
    // the child writes nothing.
    let rx = drain_pipe(child.stdout.take().unwrap());
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > Duration::from_secs(90) => {
                kill_tree(&mut child);
                let _ = rx.recv_timeout(Duration::from_secs(5));
                panic!("winiso_probe {args:?} exceeded the 90s bound");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("winiso_probe {args:?} try_wait failed: {e}"),
        }
    }
    let out = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_default();
    let text = String::from_utf8_lossy(&out);
    text.trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Seed dirs a sandbox leg can be pointed at: the fixture writes its own
/// files inside them; the run dir roots them.
#[cfg(windows)]
fn sandbox_dirs(root: &Path) -> [(&'static str, String); 4] {
    // Seed file names are the probe's fixed contract — ro-read.txt,
    // deny-read.txt, ungranted.txt.
    let mk = |name: &str, seed_file: Option<(&str, &str)>| {
        let d = root.join(name);
        std::fs::create_dir_all(&d).expect("sandbox dir");
        if let Some((fname, data)) = seed_file {
            std::fs::write(d.join(fname), data).expect("seed");
        }
        d.to_string_lossy().into_owned()
    };
    [
        ("WINISO_RO_DIR", mk("ro", Some(("ro-read.txt", "ro-data")))),
        ("WINISO_RW_DIR", mk("rw", None)),
        (
            "WINISO_DENY_DIR",
            mk("deny", Some(("deny-read.txt", "deny-data"))),
        ),
        (
            "WINISO_UNGRANTED_DIR",
            mk("ungranted", Some(("ungranted.txt", "ungranted"))),
        ),
    ]
}

/// `create_hr` values outside the handled set are evidence, not a test
/// failure — but only when they are actually HRESULT-shaped (`0x` + 8
/// hex digits). Anything else means the fixture's output contract
/// drifted, which must not pass.
#[cfg(windows)]
fn unexpected_hresult(hr: &str, leg: &str, line: &str) {
    let shaped =
        hr.len() == 10 && hr.starts_with("0x") && hr[2..].chars().all(|c| c.is_ascii_hexdigit());
    assert!(
        shaped,
        "{leg}: unparseable create_hr {hr:?} — fixture output contract drifted: {line}"
    );
    eprintln!("{leg}: unexpected create_hr {hr} — recorded, not enforced");
}

#[cfg(windows)]
fn leg_json(line: &str) -> nojson::RawJson<'static> {
    nojson::RawJson::parse(Box::leak(line.trim().to_string().into_boxed_str()))
        .unwrap_or_else(|e| panic!("leg output must be a JSON line: {e}\n{line}"))
}

#[cfg(windows)]
fn write_leg(dir: &Path, name: &str, line: &str) {
    std::fs::write(dir.join(name), format!("{}\n", line.trim())).expect("write evidence leg");
}

/// facts + contracts + host attempts: pure query legs, safe on any
/// Windows host — and on hosts without the candidate surfaces they must
/// still emit contract-valid "absent/unavailable" JSON rather than fail.
#[cfg(windows)]
#[test]
fn winiso_live_facts_contracts_attempts() {
    let Some(probe) = compiled_probe() else {
        return;
    };
    let dir = evidence_dir();
    let env = sandbox_dirs(&work_dir("live"));

    for (leg, name) in [
        (vec!["facts"], "facts.json"),
        (vec!["contracts"], "contracts.json"),
        (vec!["attempts"], "attempts-host.json"),
    ] {
        let line = run_leg(&probe, &leg, &env);
        assert!(!line.is_empty(), "{name}: probe produced no output");
        let json = leg_json(&line);
        write_leg(&dir, name, &line);
        match name {
            "facts.json" => {
                assert_eq!(s(req_member(json.value(), "mode")), "facts");
                assert!(
                    req_member(json.value(), "files")
                        .to_array()
                        .unwrap()
                        .count()
                        > 0
                );
            }
            "contracts.json" => {
                // psec/isolation_session sections exist even when every
                // field records absent.
                assert!(member(json.value(), "psec").is_some());
                assert!(member(json.value(), "isolation_session").is_some());
            }
            _ => {
                assert_eq!(s(req_member(json.value(), "mode")), "attempts");
                assert!(member(json.value(), "env_seen").is_some());
            }
        }
    }
}

/// The AppContainer baseline must still enforce and clean up — this leg
/// is the regression guard for PR-30's "現行経路を壊さない" condition.
#[cfg(windows)]
#[test]
fn winiso_live_appcontainer_baseline() {
    let Some(probe) = compiled_probe() else {
        return;
    };
    let dir = evidence_dir();
    let env = sandbox_dirs(&work_dir("live-ac"));
    let line = run_leg(&probe, &["ac-run"], &env);
    let json = leg_json(&line);
    write_leg(&dir, "ac-run.json", &line);

    assert!(b(req_member(json.value(), "profile_created")));
    assert!(b(req_member(json.value(), "spawn_ok")), "{}", line);
    for g in req_member(json.value(), "grants").to_array().unwrap() {
        assert!(b(req_member(g, "applied")));
        assert!(b(req_member(g, "restored")));
    }
    assert!(b(req_member(json.value(), "profile_deleted")));
    assert!(!b(req_member(json.value(), "cleanup_error")));
    let child = req_member(json.value(), "child");
    assert!(b(req_member(
        req_member(child, "context"),
        "is_appcontainer"
    )));
    for op in [
        "fs_write_ro",
        "fs_read_deny",
        "fs_write_deny",
        "fs_read_ungranted",
    ] {
        assert_eq!(attempt_evidence(child, op), Evidence::Denied, "{op}");
    }
}

/// PSEC leg: on a host with the contract it must enforce and clean up;
/// on a host without it the leg records `unavailable`/`exports-missing`
/// or an HRESULT — which is evidence, not a test failure. The golden
/// contract pins both shapes.
#[cfg(windows)]
#[test]
fn winiso_live_psec() {
    let Some(probe) = compiled_probe() else {
        return;
    };
    let dir = evidence_dir();
    let env = sandbox_dirs(&work_dir("live-psec"));

    let line = run_leg(&probe, &["psec-spec-test"], &env);
    let json = leg_json(&line);
    write_leg(&dir, "psec-spec.json", &line);
    // Whatever the host answers, every created env must be closed.
    if member(json.value(), "attempts").is_some() {
        for a in req_member(json.value(), "attempts").to_array().unwrap() {
            if b(req_member(a, "env_created")) {
                assert!(b(req_member(a, "closed")));
            }
        }
    } else {
        // dll_loaded:false / exports:false shapes are valid evidence.
        assert!(member(json.value(), "dll_loaded").is_some());
    }

    let ro = env[0].1.clone();
    let rw = env[1].1.clone();
    let deny = env[2].1.clone();
    let line = run_leg(
        &probe,
        &["psec-run", "--ro", &ro, "--rw", &rw, "--deny", &deny],
        &env,
    );
    let json = leg_json(&line);
    write_leg(&dir, "psec.json", &line);
    assert_eq!(s(req_member(json.value(), "mode")), "psec-run");
    match s(req_member(json.value(), "create_hr")).as_str() {
        "unavailable" | "exports-missing" => {} // feature absent on host
        "0x00000000" => {
            assert!(b(req_member(json.value(), "env_closed")));
            assert!(b(req_member(json.value(), "spawn_ok")), "{}", line);
            let child = req_member(json.value(), "child");
            for op in [
                "fs_write_ro",
                "fs_read_deny",
                "fs_write_deny",
                "fs_read_ungranted",
            ] {
                assert_eq!(attempt_evidence(child, op), Evidence::Denied, "{op}");
            }
        }
        other => unexpected_hresult(other, "psec-run", &line),
    }
}

/// Locate a Node runtime for the launch-condition legs: PATH via
/// `where.exe`, then the stock install dir. Node stands in for the
/// unpackaged interpreter class MCP servers actually are.
#[cfg(windows)]
fn node_image() -> Option<(PathBuf, PathBuf)> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(out) = Command::new("where.exe").arg("node").output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let p = PathBuf::from(line.trim());
            if p.is_file() {
                candidates.push(p);
            }
        }
    }
    candidates.push(PathBuf::from(r"C:\Program Files\nodejs\node.exe"));
    let exe = candidates.into_iter().find(|p| p.is_file())?;
    Some((exe.clone(), exe.parent()?.to_path_buf()))
}

/// Node launch conditions: the baseline AppContainer path must keep
/// spawning an unpackaged interpreter (the whole reason the existing
/// path exists), and PSEC must too if it is to be a candidate. Both
/// legs assert the process ran to a marker on stdout through the same
/// pipe plumbing MCP stdio uses.
#[cfg(windows)]
#[test]
fn winiso_live_node_launch() {
    let Some(probe) = compiled_probe() else {
        return;
    };
    let Some((node, node_dir)) = node_image() else {
        common::skip_winiso_test("node.exe not found — no interpreter launch evidence");
        return;
    };
    let dir = evidence_dir();
    let env = sandbox_dirs(&work_dir("live-node"));
    let ro = env[0].1.clone();
    let rw = env[1].1.clone();
    let deny = env[2].1.clone();
    let node_s = node.to_string_lossy().into_owned();
    let node_dir_s = node_dir.to_string_lossy().into_owned();

    let line = run_leg(
        &probe,
        &[
            "ac-run",
            "--image",
            &node_s,
            "-e",
            "console.log('node-ac-ok')",
        ],
        &env,
    );
    let json = leg_json(&line);
    write_leg(&dir, "ac-node.json", &line);
    assert!(b(req_member(json.value(), "spawn_ok")), "{}", line);
    assert_eq!(s(req_member(json.value(), "child_image")), node_s);
    assert!(
        s(req_member(json.value(), "child_stdout")).contains("node-ac-ok"),
        "node under AppContainer must reach stdout: {line}"
    );
    assert!(b(req_member(json.value(), "profile_deleted")));

    // PSEC: grant the interpreter's install dir explicitly — an
    // allowlist-style fs policy must not silently swallow the image.
    let line = run_leg(
        &probe,
        &[
            "psec-run",
            "--ro",
            &ro,
            "--ro",
            &node_dir_s,
            "--rw",
            &rw,
            "--deny",
            &deny,
            "--image",
            &node_s,
            "-e",
            "console.log('node-psec-ok')",
        ],
        &env,
    );
    let json = leg_json(&line);
    write_leg(&dir, "psec-node.json", &line);
    match s(req_member(json.value(), "create_hr")).as_str() {
        "unavailable" | "exports-missing" => {} // feature absent on host
        "0x00000000" => {
            assert!(b(req_member(json.value(), "spawn_ok")), "{}", line);
            assert!(
                s(req_member(json.value(), "child_stdout")).contains("node-psec-ok"),
                "node under PSEC must reach stdout: {line}"
            );
        }
        other => unexpected_hresult(other, "psec-node", &line),
    }
}

// ─── product legs (PR-32) ─────────────────────────────────────────────────
//
// The probe fixture above exercises the mechanisms in-process; these legs
// exercise the *product* path — `mcp-writ run --windows-mechanism <m>`
// itself — which is the acceptance surface a user actually gets. The
// launch report (`--report`) is the contract under test: the mechanism it
// records, the `os.process` observation, the final `result`, and the audit
// log the guard leaves behind.

/// Invoke `mcp-writ run --windows-mechanism <m>` with `child` as the
/// workload; returns (exit code, stderr, launch-report text if written,
/// audit-log path). The report and audit log are pointed at `evidence`
/// so the leg's own artifacts are part of the run's recorded set.
/// Bounded like `run_leg` — the workload inside is a probe leg whose
/// own waits are far tighter, so 120s only covers a wedged `mcp-writ`.
#[cfg(windows)]
fn product_run(
    work: &Path,
    evidence: &Path,
    policy: &Path,
    mechanism: &str,
    label: &str,
    child: &Path,
    child_args: &[&str],
) -> (Option<i32>, String, Option<String>, PathBuf) {
    let report_path = work.join(format!("product-{label}-report.json"));
    let audit_path = evidence.join(format!("product-{label}-audit.jsonl"));
    let mut proc = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
        .arg("run")
        .arg("--windows-mechanism")
        .arg(mechanism)
        .arg("--policy")
        .arg(policy)
        .arg("--report")
        .arg(&report_path)
        .arg("--audit-log")
        .arg(&audit_path)
        .arg("--")
        .arg(child)
        .args(child_args)
        // A validation job that exports the escape hatch must still
        // produce a real launch — the mechanism contract cannot be
        // evaluated under a skipped sandbox.
        .env_remove("MCP_WRIT_SKIP_SANDBOX")
        .env_remove("MCP_WRIT_WINDOWS_LPAC")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp-writ run");
    // Both pipes drain on reader threads: a full stderr/stdout pipe
    // would wedge the run the bound is meant to kill.
    let out_rx = drain_pipe(proc.stdout.take().unwrap());
    let err_rx = drain_pipe(proc.stderr.take().unwrap());
    let start = Instant::now();
    let status = loop {
        match proc.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() > Duration::from_secs(120) => {
                kill_tree(&mut proc);
                let _ = out_rx.recv_timeout(Duration::from_secs(5));
                let _ = err_rx.recv_timeout(Duration::from_secs(5));
                panic!(
                    "mcp-writ run --windows-mechanism {mechanism} ({label}) exceeded the 120s bound"
                );
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => panic!("mcp-writ run {label}: try_wait failed: {e}"),
        }
    };
    let _ = out_rx.recv_timeout(Duration::from_secs(10));
    let err = err_rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_default();
    (
        status.code(),
        String::from_utf8_lossy(&err).into_owned(),
        std::fs::read_to_string(&report_path).ok(),
        audit_path,
    )
}

/// Minimal JSON string escape for the synthesized refusal legs — same
/// helper shape the probe fixtures carry.
#[cfg(windows)]
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Assertions every *successful* native-mechanism launch report must
/// carry: the requested mechanism recorded verbatim, `os.process`
/// verified, and the workload's own exit recorded as `exited`.
#[cfg(windows)]
fn assert_enforced_launch(json: nojson::RawJsonValue<'_, '_>, mechanism: &str) {
    assert_eq!(
        s(req_member(
            req_member(json, "target"),
            "native_windows_mechanism"
        )),
        mechanism,
        "launch report must record the effective mechanism"
    );
    let result = req_member(json, "result");
    assert_eq!(s(req_member(result, "status")), "exited");
    assert_eq!(num(req_member(result, "exit_code")), Some(0));
    let os_process = req_member(json, "observations")
        .to_array()
        .unwrap()
        .find(|o| s(req_member(*o, "control")) == "os.process")
        .unwrap_or_else(|| panic!("launch report must carry an os.process observation"));
    assert_eq!(
        s(req_member(os_process, "state")),
        "verified",
        "the spawn observation must be verified — not merely attempted"
    );
}

/// The audit log is part of the launch contract: a run that reached the
/// launch path — enforced or refused there — leaves a non-empty JSONL
/// behind. Assert it exists and every recorded line parses as JSON.
/// (A refusal at policy load lands before the logger is created and
/// leaves no file — that shape is asserted by its own leg instead.)
#[cfg(windows)]
fn assert_audit_log(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "a launched run must leave an audit log at {}: {e}",
            path.display()
        )
    });
    let mut lines = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        leg_json(line);
        lines += 1;
    }
    assert!(
        lines > 0,
        "audit log {} must record at least one event",
        path.display()
    );
}

#[cfg(windows)]
#[test]
fn winiso_live_product_run() {
    let Some(probe) = compiled_probe() else {
        return;
    };
    let dir = evidence_dir();
    let work = work_dir("product");
    std::fs::create_dir_all(&work).expect("product work dir");

    // One policy, expressible under both mechanisms: the fixture image
    // and its build dir as literal read grants — no env allow-list, no
    // globs, no egress rules.
    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let policy_path = work.join("policy.kdl");
    std::fs::write(
        &policy_path,
        common::sandboxed_policy(
            &format!(
                "        allow \"{}\" mode=\"read\"\n        allow \"{}\" mode=\"read\"\n",
                f(probe.parent().unwrap()),
                f(&probe)
            ),
            "",
        ),
    )
    .expect("write product policy");

    // AppContainer through the product path — the launch-report contract
    // the existing mechanism already guarantees.
    let (code, stderr, report, audit) = product_run(
        &work,
        &dir,
        &policy_path,
        "appcontainer",
        "appcontainer",
        &probe,
        &["facts"],
    );
    let report = report.unwrap_or_else(|| panic!("appcontainer run must write a report: {stderr}"));
    write_leg(&dir, "product-appcontainer.json", report.trim());
    let json = leg_json(&report);
    assert_eq!(
        code,
        Some(0),
        "appcontainer run must exit cleanly: {stderr}"
    );
    assert_enforced_launch(json.value(), "appcontainer");
    assert_audit_log(&audit);

    // PSEC through the product path: either an enforced launch recorded
    // as such, or a refusal *before* launch — never a silent fallback.
    let (code, stderr, report, audit) = product_run(
        &work,
        &dir,
        &policy_path,
        "psec",
        "psec",
        &probe,
        &["facts"],
    );
    let psec_enforced = match (code, report) {
        (Some(0), Some(text)) => {
            write_leg(&dir, "product-psec.json", text.trim());
            let json = leg_json(&text);
            assert_enforced_launch(json.value(), "psec");
            true
        }
        (_, report) => {
            // The refusal is evidence too — the stage name in stderr
            // (`capability-probe`, `policy-check`, `environment-create`)
            // names where the mechanism said no.
            assert!(
                stderr.to_ascii_lowercase().contains("psec"),
                "a refused psec launch must say so — not fail opaquely: {stderr}"
            );
            write_leg(
                &dir,
                "product-psec.json",
                &format!(
                    "{{\"mode\":\"product-psec\",\"launch\":\"refused\",\"exit_code\":{},\"detail\":\"{}\"}}",
                    code.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
                    json_escape(stderr.lines().next().unwrap_or(""))
                ),
            );
            if let Some(text) = report {
                let json = leg_json(&text);
                let mechanism = member(json.value(), "target")
                    .and_then(|t| member(t, "native_windows_mechanism"))
                    .map(s);
                assert_ne!(
                    mechanism.as_deref(),
                    Some("appcontainer"),
                    "a refused psec run must not carry an appcontainer report — that is the silent fallback"
                );
                write_leg(&dir, "product-psec-report.json", text.trim());
            }
            false
        }
    };
    // The psec leg reaches the launch path on this policy — enforced or
    // refused there, its audit log must record the outcome.
    assert_audit_log(&audit);

    // Expressibility gate: a policy a PSEC spec cannot express must be
    // refused through the product path too — never silently downgraded.
    // Runs only where the probe already answered "supported"; elsewhere
    // the launch leg above already recorded the refusal class.
    if psec_enforced {
        let bad_policy = work.join("policy-env-allow.kdl");
        std::fs::write(
            &bad_policy,
            common::sandboxed_policy("", "").replace(
                "    filesystem {",
                "    environment {\n        allow \"WINISO_PRODUCT_VAR\"\n    }\n    filesystem {",
            ),
        )
        .expect("write expressibility policy");
        let (code, stderr, report, audit) = product_run(
            &work,
            &dir,
            &bad_policy,
            "psec",
            "psec-refusal",
            &probe,
            &["facts"],
        );
        assert_ne!(
            code,
            Some(0),
            "a policy with a named env allow-list must refuse under psec"
        );
        assert!(
            stderr.contains("PSEC") || stderr.to_ascii_lowercase().contains("environment"),
            "the expressibility refusal must name the cause: {stderr}"
        );
        // The refusal lands at policy load — before the launch path and
        // before the audit logger exists — so the report still records a
        // `failed` launch attributed to psec while no audit trail is
        // written (a pre-launch refusal leaving audit events would mean
        // it happened later than claimed).
        let report = report
            .unwrap_or_else(|| panic!("a refused launch must still write a report: {stderr}"));
        let json = leg_json(&report);
        assert_eq!(
            s(req_member(req_member(json.value(), "result"), "status")),
            "failed"
        );
        assert_eq!(
            s(req_member(
                req_member(json.value(), "target"),
                "native_windows_mechanism"
            )),
            "psec"
        );
        write_leg(&dir, "product-psec-refusal-report.json", report.trim());
        assert!(
            std::fs::metadata(&audit).map(|m| m.len()).unwrap_or(0) == 0,
            "a policy-load refusal must not leave an audit trail: {}",
            audit.display()
        );
        write_leg(
            &dir,
            "product-psec-refusal.json",
            &format!(
                "{{\"mode\":\"product-psec-refusal\",\"policy\":\"environment allow-list\",\"exit_code\":{},\"detail\":\"{}\"}}",
                code.unwrap_or(-1),
                json_escape(stderr.lines().next().unwrap_or(""))
            ),
        );
    }
}
