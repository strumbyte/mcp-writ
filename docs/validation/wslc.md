# WSL Containers (`wslc`) validation (PR-28)

Real-machine verification that the existing Linux Warden + MCP execution
contract holds inside a **WSL Containers** (`wslc.exe`) unit on Windows
x86-64. Scope: **`wslc run`-equivalent stdio session + substrate
capability map only** — a validation prototype driven by a dedicated
test, **not a product backend**. `EngineKind::Wslc` stays a recognized-
but-`Unsupported` vocabulary entry (`src/container/engine.rs`); nothing
in this PR enables `--engine wslc`, auto-detection, or a launch path.

Status: **environment unavailable on the reference host** — recorded
2026-10-06 · repo HEAD (PR-28 working tree) · the harness ships complete
and is wired into `scripts/validate-wslc.ps1`; every runtime claim below
is *designed*, not yet *measured*. See [Adoption decision](#adoption-decision).

## What `wslc` is — and what it is not

WSL Containers is the WSL team's container runtime, shipped with the
WSL product package (floor **WSL 2.9.3**; the validation baseline is the
**3.0.1** GA-era surface). `wslc.exe` presents a Docker-like CLI over
`wslservice` + `wslcsession.exe` user-mode services. The isolation unit
is a Linux **container** inside a per-user **session VM**: every `wslc`
container in a session shares that session's VM, VHD-backed image store,
and networks (Consommé NAT + virtiofs host shares).

Per the PR-27 vocabulary: `engine=wslc, substrate=container,
unit=container`. The session VM is *plumbing*, never a `unit=vm` claim —
the workload's neighbors are other units in the same VM. It must not be
conflated with:

- **an ordinary `wsl.exe` distro** — `wsl -l -v` distributions are
  unrelated to `wslc system session list` sessions; the suite asserts
  the distro list is undisturbed and never runs validation in a distro;
- **Docker/Podman/OCI containers** — no Docker daemon is involved;
  docker-style flags are probed for compatibility, never assumed;
- **a dedicated VM** (Kata/Hyper-V/Windows Sandbox) — units share the
  session VM; per-unit VM isolation is a different contract;
- **a user session** — the Windows logon session merely determines which
  `wslc` sessions (and thus storage) are visible.

Session ownership matters: sessions are per-user and elevation-scoped —
an elevated and a non-elevated terminal resolve to **different**
sessions with separate storage; units/images visible in one are
invisible in the other. The suite records `session_id`/`elevated` on the
host record for exactly this reason.

## Host requirements / platform refusals

`tests/wslc_container_e2e/support.rs::check_prereqs` requires **all** of:

- Windows host (`TargetOs::Windows`) on x86-64 — PR-28 validates one
  configuration first; ARM64 and older builds are unexercised, not
  claimed;
- WSL product version **≥ 2.9.3** (`src/container/windows_probe.rs::WSLC_MIN_WSL`)
  — parsed from `wsl.exe --version`; the suite **never runs
  `wsl --update`** (on the reference host that would interrupt the live
  session, touch `docker-desktop`, and disturb the pinned Kata kernel);
- `wslc --version` answers on PATH;
- `rustc` + `x86_64-unknown-linux-musl` (the guest is Linux amd64; the
  host test binary is a Windows PE, so probe and runner are
  cross-compiled with `rust-lld`);
- `cargo` for `mcp-secure-runner` (release, musl, stripped, cap marker);
- network reachability for the digest-pinned `ubuntu:24.04` amd64 pull
  (`ubuntu@sha256:008173c2…` — the same index pin as Kata/Apple);
- interactive logon (`session_id != 0`) — `wslc` session state is bound
  to a user logon; `scripts/validate-wslc.ps1` gates on this and records
  `user_interactive`/`elevated` as axes.

Missing prerequisites **skip** by default; `MCP_WRIT_REQUIRE_WSLC_TESTS=1`
fails closed (`tests/common/mod.rs::skip_wslc_test`). A skipped run never
counts as evidence, and the job's `result.json` distinguishes
`environment-unavailable` from `failed`/`wslc-tests-passed`.

No hosted runner is assumed to provide this environment: `wslc` requires
an interactive Windows logon plus the 2.9.3+ WSL package — GitHub-hosted
`windows-latest` does not guarantee either. The job is manual
(`scripts/validate-wslc.ps1`) and registered for a future
`[self-hosted, windows, wslc]` runner only.

## What the suite measures (asserted vs recorded)

Asserted = the product launch contract requires it; recorded = substrate
fact the adoption decision cites, logged to the session's evidence file.
A refused/absent capability is never silently skipped — it lands in
`capability-map.json` or the matching `*-semantics.json`.

| test | asserted | recorded → evidence |
|---|---|---|
| `wslc_environment_record` | — | WSL/wslc version text, `wslc info --format json` (GA surface; previews tolerated), `system session list`, `wsl -l -v`, `system session run uname` → `host-identity.json` |
| `wslc_cli_capability_map` | `--entrypoint`, `-e`, `--name`, `--no-healthcheck`, `-w`, `-u`, `--network none`, `-m`, `--cpus` accepted; `--privileged`, `--cap-add`, `--device`, `--platform`, `--network host`, `--restart`, `--security-opt` **refused** (a silently-accepted docker-ism fails) | `--env-file` (real file, delivery-checked), `--cidfile` (file-write checked), `-l`, `--pull`; `-v`/`--mount` winner, RO honored, single-file mounts → `capability-map.json` |
| `wslc_stdio_contract` | bidirectional stdin on `run -i` (UTF-8 incl. non-ASCII), stdout/stderr separation, stdin-EOF → exit 0, exit-code fidelity (7→7), `/dev/tty` unopenable non-TTY | full transcript → `stdio-contract.json` |
| `wslc_session_model` | default session used by `wslc run` appears in `system session list`; `wsl -l -v` distro table undisturbed | `enter <path> --name` dedicated-session creation + `--session` scoped runs (whether `enter` tolerates non-TTY stdin is itself recorded); owned-session terminate asserted *only when* `enter` succeeded; raw session tables, storage listing → `session-model.json` + `lifecycle.json` |
| `wslc_share_semantics` | RW write succeeds, **RO write denied**, unicode+space file reads, unicode+space *dir* mounts | case-folding result, reparse-point visibility (when creatable), mount entries → `share-semantics.json` |
| `wslc_network_semantics` | `--network none` cuts DNS+TCP in-guest | `-p` publish reachability (`PROBE-LISTEN-OK`) — recorded, not asserted: the `run -i` launch contract never publishes ports; routes/resolver dump, Consommé DNS results, host-loopback form (default-gateway vs `host.*` name), IPv6 presence → `network-semantics.json` |
| `wslc_stdio_session` | the runner-wrapped secure image serves init→`tools/list`→10 legs identical to Kata/Apple; `NoNewPrivs=1`, `Seccomp=2`, virtiofs present, `cmdline_has_kata=false`; `wslc list`/`inspect` = running; EOF → exit 0; report `exited` + `FullyEnforced` + Landlock/seccomp confirmations; audit allows+denies | first/last/exit timings → `metrics.json` + `report/report.json` + `logs/audit.jsonl` |
| `wslc_stop_terminates_and_cleans_up` | `wslc kill -s SIGINT` accepted → unit leaves `running`; attached client exits; session still serves; inspect record kept | unit inspect, CLI exit, `interrupted` report flag → `lifecycle.json` |
| `wslc_cli_death_and_launch_failure` | bad `--entrypoint` refuses at launch; `wslc exec` on a dead unit refuses; owned unit removal | whether the unit survives CLI death (daemon-owned) or is torn down → `lifecycle.json` |
| `wslc_storage_layout` | — | `wslc info`, `images`/`image inspect` (digest identity), `%LOCALAPPDATA%\wslc` tree shape, per-drive free space, dedicated-session VHD before/after terminate → `storage.json` |

The runner-wrapped session mounts the baked *secure* image form
(`wslc build` FROM the pinned base + runner/probe/policy + `MCP_ORIG_*`
env — the wrap contract) with policy `:ro` — a single file where the
substrate mounts files, its holding dir at `/etc/mcp-secure` otherwise
(`capability-map.json` records which). A session VM whose kernel cannot
fully apply Landlock/seccomp makes the runner refuse launch (no
`allow_degraded` in the fixture policy) — that refusal is itself the
adoption-relevant finding, recorded in the session's report evidence.

## Owned-resource / cleanup contract

The suite creates **only**:

- images tagged `mcp-writ-wslc-probe:test`,
  `mcp-writ-wslc-probe-secure:test` inside the *default* session's store;
- units named `mcp-writ-wslc-*` (`--rm` attached; `UnitGuard` `rm -f`s
  named units on any path incl. panic);
- dedicated sessions `mcp-writ-wslc-sess-*`/`mcp-writ-wslc-store-*` with
  explicit storage under `MCP_WRIT_WSLC_SESSION_ROOT` (job-set, else
  `target/wslc-tests/session-storage`) — fully test-owned;
- scratch dirs under `MCP_WRIT_WSLC_TEST_ROOT` (job-set, else
  `target/wslc-tests`).

It **never**: runs `wsl --update`/`wsl --shutdown`, terminates a session
it did not name, prunes images broadly, or touches `wsl.exe` distros /
Docker state / foreign `wslc` sessions. Session termination is a
potentially destructive op — the owned-session legs target the exact
`--session` name only. `scripts/clean-test-container-artifacts.sh` owns
the *image* sweep (`wslc image rm`/`rmi` on the `mcp-writ-wslc-*` tags,
bounded `wslc` probe first — only when `wslc` answers, only test tags);
the validation run's own `work/` tree (incl. session-storage VHDs) is
deleted by the validate script's verified-path cleanup.

## Reproducing (manual job)

```powershell
# Windows x86-64, interactive session, WSL >= 2.9.3, wslc on PATH
scripts\validate-wslc.ps1 [-Repetitions 3]
```

The script: records host identity (commit, OS build, session id,
interactive/elevated, rustc, `wsl.exe --version`, `wslc --version`,
`wsl -l -v`, `wslc system session list`) → disk gates every drive it
writes to (target dir, TEMP, LOCALAPPDATA — the default session store —
session root; `cargo clean` once under 40 GiB, then fail) →
environment gate (`environment-unavailable` recorded distinctly) →
`MCP_WRIT_REQUIRE_WSLC_TESTS=1` + TEST_ROOT/EVIDENCE_DIR/SESSION_ROOT →
`cargo test --locked --test wslc_container_e2e -- --nocapture` →
evidence accounting (`metrics.json` per repetition with guest report +
audit, ≥3 `lifecycle.json`, every `*-semantics.json`/record present) →
`result.json`. Direct run without the job wrapper:

```
MCP_WRIT_REQUIRE_WSLC_TESTS=1 cargo test --locked --test wslc_container_e2e -- --nocapture
```

## Current-host record (2026-10-06)

The reference host for this PR (the same machine that ran PR-25):
Windows 11 Pro 25H2 `10.0.26200.9457` x86-64, interactive session 1.
The environment gate's findings:

| prerequisite | observed | verdict |
|---|---|---|
| WSL product | **2.4.12.0** | below the 2.9.3 floor |
| `wslc` CLI | **absent** on PATH | unavailable |
| Windows build | 26200.9457 (25H2) | recorded |
| distros | Ubuntu (this session), docker-desktop | untouched |
| free space | D: ~42 GiB, C: ~17 GiB | session/build roots on D:/WSL ext4 per `AGENTS.md` |

`wsl --update` was deliberately **not** run: it would interrupt this
live WSL session, touch the `docker-desktop` distro, and disturb the
pinned Kata guest-kernel setup (5.15.167.4 module set) that PR-25's
evidence depends on. Manufacturing prerequisites is not validation.

## Adoption decision

**Deferred — environment unavailable.** The decision is recorded, not
implied:

- `EngineKind::Wslc` remains `resolve_engine → Unsupported`; no product
  launch path, no auto-detect, no fallback exists or is added;
- the fail-closed harness + validate job ship now so a conforming host
  produces the full evidence set mechanically;
- adoption is re-evaluated on a host meeting the floor (WSL ≥ 2.9.3,
  `wslc` present, interactive x86-64 Windows), requiring at minimum:
  every `required` capability-map leg honored; stdio contract clean;
  RO shares enforced; `--network none` deny; the
  runner-wrapped session reaching `FullyEnforced` (Landlock + seccomp +
  no_new_privs) — the kernel-level gate no substrate fact substitutes.

### Version-bump reevaluation axes (per PR-28)

If the baseline moves past 3.0.1, re-measure: the `wslc` CLI/arg surface
(flat vs `container`/`image`/`system` noun dialects — the suite already
probes both), session sharing model (`enter`/`--session` scoping),
virtiofs mount spellings and RO enforcement, Consommé network semantics
(DNS/host-loopback/`-p`/`none`), guest-control enforcement depth, and
stop/kill/termination semantics. Windows build updates and WSL **Store
package** updates are recorded as *separate axes* in `host-identity.json`
(`os`/`os_revision` vs `wsl_version_text`) — a Store update can move the
`wslc` surface on a fixed Windows build.

### Unverified (explicitly, on this host)

Every runtime claim in the capability table — CLI acceptance/refusal,
session model, shares, Consommé, lifecycle, storage, guest-control —
is **unverified** until a conforming host runs the suite. Additionally
unexamined by design: enterprise policy interaction (the WSL group
policies/Intune knobs that can disable `wslc`), MDE/AV plug-in
compatibility with `wslservice`/`wslcsession.exe`, ARM64, elevated-vs-
non-elevated divergence beyond the recorded axes, and Windows-container
workloads (the suite validates Linux amd64 only — the product contract's
target). These must each be checked individually before any `wslc`
backend ships; none is implied by this document.

## Fixture and test inventory

- `tests/fixtures/wslc/wslc_probe_server.rs` — std-only static musl
  probe; argv mode measures the substrate (stdio/tty/identity/
  share-probe/case-probe/reparse-probe/net-*/sleep), bare mode serves
  the shared MCP tool loop (same deny-attribution legs as Kata).
- `tests/fixtures/wslc/policy.kdl` — the Kata fixture policy contract,
  `server "wslc-probe"`; no `allow_degraded` (a partially-enforced
  session must refuse, and the refusal is the finding).
- `tests/wslc_container_e2e/` — the 10 tests above (`main.rs` crate
  root + `support`/`cli`/`stdio`/`substrate`/`lifecycle` modules);
  `tests/common/mod.rs::skip_wslc_test` the gate.
- `scripts/validate-wslc.ps1` — the fail-closed manual job
  (`.local/wslc-validation/<utc>-<guid>/{work,evidence,result.json}`).
