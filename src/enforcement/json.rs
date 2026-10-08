//! JSON serialization of the launch-report model and `plan`
//! diagnostics via `nojson` (same style as `audit_log`).

use super::model::*;
use super::plan::{PlanCheck, PlanReport};

// ---------------------------------------------------------------------------
// JSON serialization (nojson — same style as audit_log.rs)
// ---------------------------------------------------------------------------

/// Outputs the JSON literal `null`.
pub(super) struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Emits already-validated JSON text verbatim. Used to embed the guest
/// report inside the host report without re-interpreting its content —
/// the caller must have parsed the text before reaching for this.
struct JsonRaw<'a>(&'a str);

impl nojson::DisplayJson for JsonRaw<'_> {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

fn write_runner_identity(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    r: &GuestRunnerIdentity,
) -> std::fmt::Result {
    f.member("version", r.version.as_str())?;
    f.member(
        "capabilities",
        nojson::array(|f| {
            for c in &r.capabilities {
                f.element(c.as_str())?;
            }
            Ok(())
        }),
    )
}

fn write_guest_link(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    g: &GuestReportLink,
) -> std::fmt::Result {
    f.member("state", g.state.as_str())?;
    match &g.detail {
        Some(d) => f.member("detail", d.as_str()),
        None => f.member("detail", JsonNull),
    }?;
    match &g.runner {
        Some(r) => f.member("runner", nojson::object(|f| write_runner_identity(f, r))),
        None => f.member("runner", JsonNull),
    }?;
    match &g.report_json {
        Some(j) => f.member("report", JsonRaw(j.as_str())),
        None => f.member("report", JsonNull),
    }
}

fn write_isolation(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    i: &IsolationRecord,
) -> std::fmt::Result {
    f.member("configured", i.configured.name())?;
    match i.verified {
        Some(v) => f.member("verified", v.name()),
        None => f.member("verified", JsonNull),
    }?;
    match i.unit {
        Some(u) => f.member("unit", u.name()),
        None => f.member("unit", JsonNull),
    }?;
    match &i.unit_id {
        Some(id) => f.member("unit_id", id.as_str()),
        None => f.member("unit_id", JsonNull),
    }?;
    match &i.detail {
        Some(d) => f.member("detail", d.as_str()),
        None => f.member("detail", JsonNull),
    }
}

fn write_control(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    c: &PlannedControl,
) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("layer", c.layer.as_str())?;
    f.member("mechanism", c.mechanism)?;
    f.member("state", c.state.as_str())?;
    match &c.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

fn write_subject(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    s: &GrantSubject,
) -> std::fmt::Result {
    match s {
        GrantSubject::FsPath { path, access } => {
            f.member("kind", "fs_path")?;
            f.member("path", path.as_str())?;
            f.member("access", access.as_str())
        }
        GrantSubject::TcpConnect { port } => {
            f.member("kind", "tcp_connect")?;
            f.member("port", *port)
        }
        GrantSubject::Capability { name } => {
            f.member("kind", "capability")?;
            f.member("name", name.as_str())
        }
        GrantSubject::Syscall { name } => {
            f.member("kind", "syscall")?;
            f.member("name", name.as_str())
        }
        GrantSubject::PrivateTmpdir => f.member("kind", "private_tmpdir"),
        GrantSubject::Rule { kind, name } => {
            f.member("kind", *kind)?;
            f.member("name", name.as_str())
        }
    }
}

fn write_grant(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    g: &ProcessGrant,
) -> std::fmt::Result {
    f.member("subject", nojson::object(|o| write_subject(o, &g.subject)))?;
    match &g.origin {
        GrantOrigin::Tool(name) => {
            f.member(
                "origin",
                nojson::object(|o| {
                    o.member("kind", "tool")?;
                    o.member("name", name.as_str())
                }),
            )?;
        }
        origin => f.member("origin", origin.kind())?,
    }
    f.member("state", g.state.as_str())?;
    match &g.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

fn write_tool(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    t: &ToolDisposition,
) -> std::fmt::Result {
    f.member("name", t.name.as_str())?;
    match &t.server {
        Some(s) => f.member("server", s.as_str()),
        None => f.member("server", JsonNull),
    }?;
    f.member("allowed", t.allowed)?;
    match &t.side_effect {
        Some(s) => f.member("side_effect", s.as_str()),
        None => f.member("side_effect", JsonNull),
    }
}

fn write_observation(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    o: &EnforcementObservation,
) -> std::fmt::Result {
    f.member("control", o.control)?;
    f.member("state", o.state.as_str())?;
    f.member("basis", o.basis.as_str())?;
    f.member("phase", o.phase.as_str())?;
    match &o.reason {
        Some(r) => f.member("reason", r.as_str()),
        None => f.member("reason", JsonNull),
    }
}

fn write_identity_pin(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    p: &IdentityPin,
) -> std::fmt::Result {
    f.member("type", p.hash_type)?;
    f.member("target", p.target.as_str())?;
    f.member("hash", p.hash.as_str())?;
    f.member("role", p.role.as_str())?;
    f.member(
        "checks",
        nojson::array(|f| {
            for c in &p.checks {
                f.element(c.as_str())?;
            }
            Ok(())
        }),
    )
}

fn write_code_identity(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    c: &CodeIdentity,
) -> std::fmt::Result {
    f.member("kind", c.kind.as_str())?;
    match &c.resolved {
        Some(r) => f.member("resolved", r.as_str()),
        None => f.member("resolved", JsonNull),
    }?;
    f.member(
        "pins",
        nojson::array(|f| {
            for p in &c.pins {
                f.element(nojson::object(|o| write_identity_pin(o, p)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "pinned",
        nojson::array(|f| {
            for s in &c.pinned {
                f.element(s.as_str())?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "mutable",
        nojson::array(|f| {
            for s in &c.mutable {
                f.element(s.as_str())?;
            }
            Ok(())
        }),
    )
}

impl EnforcementPlan {
    fn write_json(&self, f: &mut nojson::JsonObjectFormatter<'_, '_, '_>) -> std::fmt::Result {
        f.member(
            "controls",
            nojson::array(|f| {
                for c in &self.controls {
                    f.element(nojson::object(|o| write_control(o, c)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "grants",
            nojson::array(|f| {
                for g in &self.grants {
                    f.element(nojson::object(|o| write_grant(o, g)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "tools",
            nojson::array(|f| {
                for t in &self.tools {
                    f.element(nojson::object(|o| write_tool(o, t)))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "limitations",
            nojson::array(|f| {
                for l in &self.limitations {
                    f.element(l.as_str())?;
                }
                Ok(())
            }),
        )
    }
}

impl LaunchReport {
    /// Serialize the report as one JSON object (schema version
    /// [`LAUNCH_REPORT_SCHEMA_VERSION`]).
    pub fn to_json(&self) -> String {
        let report = self;
        let launch_id = report.launch_id.to_string();
        nojson::object(|f| {
            f.member("schema_version", report.schema_version)?;
            f.member("launch_id", launch_id.as_str())?;
            f.member("created_at", report.created_at.as_str())?;
            f.member(
                "target",
                nojson::object(|f| {
                    f.member("host_os", report.target.host_os.name())?;
                    f.member("substrate_os", report.target.substrate_os.name())?;
                    f.member("workload_os", report.target.workload_os.name())?;
                    f.member("workload_arch", report.target.workload_arch.name())?;
                    f.member("substrate", report.target.substrate.name())?;
                    match report.target.engine {
                        Some(engine) => f.member("engine", engine.name()),
                        None => f.member("engine", JsonNull),
                    }?;
                    // The effective native-Windows mechanism — the
                    // explicit selection, else the platform default
                    // (AppContainer) for a native Windows target; null
                    // where no native Windows mechanism applies.
                    match report.target.effective_windows_mechanism() {
                        Some(m) => f.member("native_windows_mechanism", m.name()),
                        None => f.member("native_windows_mechanism", JsonNull),
                    }
                }),
            )?;
            match &report.policy {
                Some(p) => f.member(
                    "policy",
                    nojson::object(|f| {
                        f.member("id", p.id.as_str())?;
                        f.member("version", p.version.as_str())?;
                        f.member("hash", p.hash.as_str())
                    }),
                )?,
                None => f.member("policy", JsonNull)?,
            }
            f.member("dry_run", report.dry_run)?;
            f.member("plan", nojson::object(|f| report.plan.write_json(f)))?;
            f.member(
                "observations",
                nojson::array(|f| {
                    for o in &report.observations {
                        f.element(nojson::object(|o2| write_observation(o2, o)))?;
                    }
                    Ok(())
                }),
            )?;
            match &report.result {
                Some(r) => f.member(
                    "result",
                    nojson::object(|f| {
                        f.member("status", r.status)?;
                        match &r.detail {
                            Some(d) => f.member("detail", d.as_str()),
                            None => f.member("detail", JsonNull),
                        }?;
                        match r.exit_code {
                            Some(c) => f.member("exit_code", c),
                            None => f.member("exit_code", JsonNull),
                        }
                    }),
                ),
                None => f.member("result", JsonNull),
            }?;
            match &report.code_identity {
                Some(c) => f.member(
                    "code_identity",
                    nojson::object(|f| write_code_identity(f, c)),
                ),
                None => f.member("code_identity", JsonNull),
            }?;
            match &report.guest_runner {
                Some(r) => f.member(
                    "guest_runner",
                    nojson::object(|f| write_runner_identity(f, r)),
                ),
                None => f.member("guest_runner", JsonNull),
            }?;
            match &report.guest {
                Some(g) => f.member("guest", nojson::object(|f| write_guest_link(f, g))),
                None => f.member("guest", JsonNull),
            }?;
            match &report.isolation {
                Some(i) => f.member("isolation", nojson::object(|f| write_isolation(f, i))),
                None => f.member("isolation", JsonNull),
            }
        })
        .to_string()
    }

    /// Serialize and write to `path`, replacing an existing file.
    ///
    /// `--report` semantics: every launch attempt overwrites the report
    /// path — the file always describes the most recent launch. The
    /// caller decides the exit code; a write error is never success.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }
}

fn write_check(f: &mut nojson::JsonObjectFormatter<'_, '_, '_>, c: &PlanCheck) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("status", c.status.as_str())?;
    match &c.detail {
        Some(d) => f.member("detail", d.as_str()),
        None => f.member("detail", JsonNull),
    }?;
    match &c.remediation {
        Some(r) => f.member("remediation", r.as_str()),
        None => f.member("remediation", JsonNull),
    }
}

impl PlanReport {
    /// Serialize the plan result as one JSON object (schema version
    /// [`PLAN_REPORT_SCHEMA_VERSION`](crate::enforcement::PLAN_REPORT_SCHEMA_VERSION)).
    /// `reason` serializes as
    /// `{code, detail}` — both parts stay machine-readable.
    pub fn to_json(&self) -> String {
        let report = self;
        nojson::object(|f| {
            f.member("schema_version", report.schema_version)?;
            f.member("created_at", report.created_at.as_str())?;
            f.member("status", report.status.as_str())?;
            match (&report.reason_code, &report.reason) {
                (Some(code), detail) => f.member(
                    "reason",
                    nojson::object(|f| {
                        f.member("code", *code)?;
                        match detail {
                            Some(d) => f.member("detail", d.as_str()),
                            None => f.member("detail", JsonNull),
                        }
                    }),
                ),
                _ => f.member("reason", JsonNull),
            }?;
            f.member(
                "target",
                nojson::object(|f| {
                    f.member("host_os", report.target.host_os.name())?;
                    f.member("substrate_os", report.target.substrate_os.name())?;
                    f.member("workload_os", report.target.workload_os.name())?;
                    f.member("workload_arch", report.target.workload_arch.name())?;
                    f.member("substrate", report.target.substrate.name())?;
                    match report.target.engine {
                        Some(engine) => f.member("engine", engine.name()),
                        None => f.member("engine", JsonNull),
                    }?;
                    match report.target.effective_windows_mechanism() {
                        Some(m) => f.member("native_windows_mechanism", m.name()),
                        None => f.member("native_windows_mechanism", JsonNull),
                    }
                }),
            )?;
            match &report.policy {
                Some(p) => f.member(
                    "policy",
                    nojson::object(|f| {
                        f.member("id", p.id.as_str())?;
                        f.member("version", p.version.as_str())?;
                        f.member("hash", p.hash.as_str())
                    }),
                )?,
                None => f.member("policy", JsonNull)?,
            }
            f.member(
                "checks",
                nojson::array(|f| {
                    for c in &report.checks {
                        f.element(nojson::object(|o| write_check(o, c)))?;
                    }
                    Ok(())
                }),
            )?;
            f.member(
                "remediation",
                nojson::array(|f| {
                    for r in &report.remediation {
                        f.element(r.as_str())?;
                    }
                    Ok(())
                }),
            )?;
            match &report.plan {
                Some(p) => f.member("plan", nojson::object(|f| p.write_json(f))),
                None => f.member("plan", JsonNull),
            }
        })
        .to_string()
    }
}
