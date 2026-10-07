# WSL Containers (`wslc`) validation (PR-28)

Real-machine verification that the existing Linux Warden + MCP execution
contract holds inside a **WSL Containers** (`wslc.exe`) unit on Windows
x86-64. PR-28's scope was a **`wslc run`-equivalent stdio session +
substrate capability map** driven by a dedicated test; the *product*
backend (`--engine wslc` on `run-image`/`wrap-image`/`containerize`/
`plan --image`, explicit selection only) was wired and measured in
PR-29 — see [Product-path integration](#product-path-integration-pr-29).

Status: **measured on the reference host — `wslc-tests-passed`** —
recorded 2026-10-06 · PR-28 working tree · WSL **3.0.1.0** / `wslc`
**3.0.1.0** / session-VM kernel **6.18.40.1-microsoft-standard-WSL2** /
Windows 26200.9457 x86-64, interactive session 1, non-elevated. All 12
tests passed; the measured evidence set lives under
`.local/wslc-validation/20261006-041445-60d7c54ba712416db8603eb34f7eebd0/`
(prior run: `20261006-030108-…`, 10/10). The PR-29 product-path suite
re-ran the full gated set as **16/16** on the same host (record below).
See [Adoption decision](#adoption-decision).

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
| `wslc_share_semantics` | RW write succeeds, **RO write denied**, unicode+space file reads, unicode+space *dir* mounts | case-folding result, reparse-point visibility (when creatable), **Windows ACL leg**: `icacls /deny <user>:R` on a test-owned file → guest `stat` ok, `open` → EACCES (`acl_denied=true` — host DACLs reach through virtiofs), mount entries → `share-semantics.json` |
| `wslc_network_semantics` | `--network none` cuts DNS+TCP in-guest | `-p` publish reachability (`PROBE-LISTEN-OK`) — recorded, not asserted: the `run -i` launch contract never publishes ports; routes/resolver dump, Consommé DNS results, host-loopback form (default-gateway vs `host.*` name), IPv6 presence → `network-semantics.json` |
| `wslc_stdio_session` | the runner-wrapped secure image serves init→`tools/list`→10 legs identical to Kata/Apple; `NoNewPrivs=1`, `Seccomp=2`, virtiofs present, `cmdline_has_kata=false`; `wslc list`/`inspect` = running; EOF → exit 0; report `exited` + `FullyEnforced` + Landlock/seccomp confirmations; audit allows+denies | first/last/exit timings → `metrics.json` + `report/report.json` + `logs/audit.jsonl` |
| `wslc_stop_terminates_and_cleans_up` | `wslc kill -s SIGINT` accepted → unit leaves `running`; attached client exits; session still serves; inspect record kept | unit inspect, CLI exit, `interrupted` report flag → `lifecycle.json` |
| `wslc_cli_death_and_launch_failure` | bad `--entrypoint` refuses at launch; `wslc exec` on a dead unit refuses; owned unit removal | whether the unit survives CLI death (daemon-owned) or is torn down → `lifecycle.json` |
| `wslc_mrtr_and_wire_stress` | MRTR (2026-07-28 `input_required`): interim forwards verbatim with `elicitation` capability; retry on a **new id** with `requestState`+`inputResponses` completes (`resultType:complete`); same call **without** the capability is refused `-32001`; 512 KiB single-frame result arrives whole | interim/retry/denied payloads, audit `additional-request` + deny records → `mrtr.json` + `logs/audit.jsonl` |
| `wslc_perf_stats` | — | warm `run -i` round-trips ×7 → median/p95; guest `VmPeak`/`VmRSS`/`VmSize` + cgroup current/peak/max; host session-VM working set; cold dedicated-session `enter` + first-run times → `perf-stats.json` |
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
Windows 11 Pro 25H2 `10.0.26200.9457` x86-64, interactive session 1,
non-elevated. The host was updated in-session per the adopted direction:
the Store WSL package was already at **3.0.1.0**, and a WSL shutdown/
restart loaded the 3.0.1 payload (`wslc.exe` resolves from
`C:\Program Files\WSL\wslc.exe` — the package does not put that dir on
PATH; `validate-wslc.ps1` prepends it and records `wslc_path_added`).

| prerequisite | observed | verdict |
|---|---|---|
| WSL product | **3.0.1.0** | at/above the 2.9.3 floor |
| `wslc` CLI | **3.0.1.0** (`C:\Program Files\WSL\wslc.exe`, PATH-augmented) | present |
| session manager | `SessionManagerVersion` **3.0.1** (`wslc info`) | recorded |
| session-VM kernel | **6.18.40.1-microsoft-standard-WSL2** | recorded |
| Windows build | 26200.9457 (25H2) | recorded |
| distros | Ubuntu (this session), docker-desktop | identical before/after |
| session store root | **`D:\wslc`** (`settings.yaml session.storagePath`, set before first session) | D:-placed as required |
| free space | D: ~47 GiB (bulk target), C: ~15 GiB (settings only) | write drives gated |

`wsl --update` ran only after the package was already current — it was a
restarting into the already-installed 3.0.1 payload, not a channel move.
The update cycle stopped this WSL session and `docker-desktop` briefly;
both recovered. Runs: `scripts\validate-wslc.ps1` → **12/12 passed,
`wslc-tests-passed`** (64 s), evidence under
`.local/wslc-validation/20261006-041445-60d7c54ba712416db8603eb34f7eebd0/`;
the earlier 10-test run lives under `20261006-030108-…`.

### Measured surface (the numbers behind the claims)

- **stdio contract** (`stdio-contract.json`): bidirectional stdin echo
  (UTF-8 incl. non-ASCII), stderr kept separate, stdin-EOF → exit 0,
  exit-code fidelity (7→7), `/dev/tty` unopenable under `run -i`
  non-TTY (`fd0=/dev/null`, fd1/fd2 pipes).
- **Capability map** (`capability-map.json`): `--entrypoint`, `-e`,
  `--name`, `--no-healthcheck`, `-w`, `-u`, `--network none`, `-m`,
  `--cpus`, `--env-file`, `--cidfile`, `-l`, `--pull` all accepted;
  `--privileged`, `--cap-add`, `--device`, `--platform`,
  `--network host`, `--restart`, `--security-opt` all **refused** — no
  silent Docker-ism acceptance. Mount contract: `-v` honored
  (RW+RO enforced), **`--mount` not implemented**, single-file mounts OK.
- **Session model** (`session-model.json`): plain `wslc run` uses the
  default session (`wslc-cli-yuzame`); a bare storage path is refused by
  `system session enter` (`ERROR_PATH_NOT_FOUND` —
  `WSLCSessionStorageFlagsNoCreate`: `enter` reattaches *existing*
  storage only; fresh dedicated stores are SDK-only via
  `WslcCreateSession`). Seeding a test-owned dir with a copy of the
  default `storage.vhdx` + `enter --name` creates a working dedicated
  session; `--session <name>` scoping works; owned-session
  `terminate --session` works; `wsl -l -v` distro table undisturbed.
  Session VHD **persists** after session end (`storage.json`
  before/after: 931 MB → re-listed after terminate).
- **virtiofs** (`share-semantics.json`): RW write ok, **RO write denied
  (EROFS)**, unicode + space + nested names read, case-folding observed,
  directory **symlink visible but dereference denied** (EPERM — the
  host-reparse-point leg), unicode+space dir mount ok. **Windows ACL
  leg**: a test-owned file with `icacls /deny <current-user>:R` stays
  stat-able (`metadata=ok`) but `open` fails with **EACCES** in the
  guest — host DACLs propagate through the virtiofs share. The deny ACE
  is applied to a file the test created and is removed by a drop guard
  before cleanup.
- **Consommé network** (`network-semantics.json`): in-guest DNS resolves
  `localhost` and `example.com`; `host.docker.internal` resolves to the
  host's LAN address (192.168.11.238) but TCP connect refused (host
  loopback **not** bridged — recorded, not asserted; the launch contract
  never needs it); `host.containers.internal`/`host.internal` do not
  resolve; IPv6 loopback connect fails (no in-guest IPv6 route);
  **`--network none` cuts DNS+TCP** (asserted); **`-p 127.0.0.1:…:8080`
  publish works** (`PROBE-LISTEN-OK` reached from the host).
- **Guest enforcement** (`report/report.json` observations):
  `no_new_privs` confirmed in pre_exec; **Landlock FullyEnforced
  (kernel ABI v7)**; seccomp program confirmed; real denials verified
  in-guest — `chmod` → EPERM (seccomp), TCP connect → EPERM
  (network deny), `/etc` write → EACCES + `/etc/hostname` read →
  EACCES (Landlock), `/etc/shadow` → RPC-layer deny (secret overlay),
  unknown tool → auditor deny; audit log carries
  `tool_call.denied` + `mcp_message.allowed`.
- **MRTR + wire stress** (`mrtr.json`, `policy_mrtr.kdl` v2 policy):
  on the 2026-07-28 wire the `mrtr_probe` call returns an
  `input_required` interim whose `elicitation/create` inputRequest
  reaches the client verbatim; a retry under a **new JSON-RPC id**
  carrying `requestState` + `inputResponses` is an independent
  `tools/call` at the gate and completes (`resultType:"complete"`,
  `mrtr-ok answered=[github_login]`); the same call **without** the
  `elicitation` client capability is refused `-32001
  (capability)` instead of forwarding the interim. Audit records both
  the allowed `additional-request` and the denied retry-path verdict.
  Slow peer: `slow_echo` holds the response **2.001 s** (measured) and
  the transport still delivers it. Excessive output: `big_text`
  returns a **524,402-byte** single frame, delivered whole (BIGEND
  sentinel verified). Substrate note: on a 2026-07-28 wire *every*
  `result` must declare `resultType` — the proxy denies an absent
  member (`result-type`), so the probe emits
  `"resultType":"complete"` when `params._meta` pins 2026.
- **Lifecycle** (`lifecycle.json`): `wslc kill -s SIGINT` → unit exits,
  attached CLI exit 130, report `interrupted`, session keeps serving;
  **killing the `wslc` client leaves the unit running** (daemon-owned —
  recorded); bad `--entrypoint` refused at launch (`E_INVALIDARG`);
  `wslc exec` on a dead unit refused; owned unit removed.
- **Timings** (`metrics.json` + `perf-stats.json`): stdio-session point
  samples — first response 0.28 s, last response 0.50 s,
  exit-after-EOF 0.64 s, `stop` → gone in 0.42 s. Cold/warm split
  (`wslc_perf_stats`): **warm** `run -i` probe round-trip ×7 → median
  **0.406 s**, p95 **0.805 s** (range 0.404–0.805); **cold** dedicated
  session — `enter` on a seeded store 0.718 s, first `run` 3.115 s.
  RSS: guest probe `VmPeak` 780 kB / `VmRSS` 544 kB / `VmSize` 784 kB,
  cgroup `memory.current` ≈3.6 MB / `peak` ≈5.4 MB / `max`=unlimited;
  host session-VM working set ≈78 MB. Provisional adoption bars
  (warm median ≤1 s, cold first-run ≤5 s) are met; `-Repetitions`
  multi-run medians are not yet taken.

## Adoption decision

**Adoptable as an ordinary container substrate; the dedicated-VM
guarantee is declined.** Recorded on the measured 3.0.1 surface:

- `engine=wslc, substrate=container, unit=container` holds — every
  required capability-map leg honored, stdio contract clean, RO mounts
  enforced, `--network none` denies, the runner-wrapped session reaches
  `FullyEnforced` (Landlock ABI v7 + seccomp + no_new_privs verified in
  the guest);
- **per-container dedicated VM is not a WSLC guarantee**: units in a
  session share that session's VM/VHD/network — `unit=vm` stays
  unclaimed, matching the PR-27 vocabulary;
- `EngineKind::Wslc` remained `resolve_engine → Unsupported` at this
  record's date — this PR measured; the launch path was wired later by
  PR-29 (see [Product-path integration (PR-29)](#product-path-integration-pr-29)
  below);
- residual gaps are explicit below, not implied away.

### Version-bump reevaluation axes (per PR-28)

If the baseline moves past 3.0.1, re-measure: the `wslc` CLI/arg surface
(flat vs `container`/`image`/`system` noun dialects — the suite already
probes both), session sharing model (`enter`/`--session` scoping),
virtiofs mount spellings and RO enforcement, Consommé network semantics
(DNS/host-loopback/`-p`/`none`), guest-control enforcement depth, and
stop/kill/termination semantics. Windows build updates and WSL **Store
package** updates are recorded as *separate axes* in `host-identity.json`
(`os`/`os_revision` vs `wsl_version_text`) — a Store update can move the
`wslc` surface on a fixed Windows build. The SDK axis is different in
kind — `wslcsdk.h` is a source-inspected contract, not an exercised
call — so a bump check starts from `wslc --version`/`info` drift plus a
re-run of the gated suite, and each enterprise interaction below (policy
prohibition, MDE plug-in interference) is its own axis to re-measure on
the affected host class, not a reason to guess compatibility.

### Unverified / not-exercised (explicitly, on this host)

Measured legs above are verified; the following were **not** exercised
and must be checked before any `wslc` backend ships:

- **SDK (`wslcsdk.h`) calls** — source-inspected for the session
  contract (`WslcCreateSession` creates fresh stores; `enter` is
  NoCreate); not compiled or invoked;
- **multi-repetition statistics** — warm median/p95 come from a single
  validate run's 7 in-process rounds; `validate-wslc.ps1 -Repetitions`
  exists but has not been run >1;
- **enterprise policy / Intune interaction, MDE/AV plug-in
  compatibility with `wslservice`/`wslcsession.exe`, ARM64, elevated-vs-
  non-elevated divergence, Windows-container workloads** — unexamined
  by design;
- **exit-code propagation note**: `wslc run` propagates the unit's exit
  code directly (measured 7→7) — unlike the Windows docker CLI, which
  does not propagate and requires `.State.ExitCode`.

## Fixture and test inventory

- `tests/fixtures/wslc/wslc_probe_server.rs` — std-only static musl
  probe; argv mode measures the substrate (stdio/tty/identity/
  share-probe/case-probe/reparse-probe/net-*/sleep/mem-probe), bare
  mode serves the shared MCP tool loop (same deny-attribution legs as
  Kata, plus `mrtr_probe`/`slow_echo`/`big_text` for the wire legs).
- `tests/fixtures/wslc/policy.kdl` — the Kata fixture policy contract,
  `server "wslc-probe"`; no `allow_degraded` (a partially-enforced
  session must refuse, and the refusal is the finding).
- `tests/fixtures/wslc/policy_mrtr.kdl` — the v2 variant for the MRTR
  leg (`mcp { allow "elicitation/create" }`,
  `tool "mrtr_probe" input_responses="allow"`); the probe adds
  `mrtr_probe`/`slow_echo`/`big_text` tools and an argv `mem-probe`.
- `tests/wslc_container_e2e/` — the 12 tests above (`main.rs` crate
  root + `support`/`cli`/`stdio`/`substrate`/`lifecycle` modules);
  `tests/common/mod.rs::skip_wslc_test` the gate.
- `scripts/validate-wslc.ps1` — the fail-closed manual job
  (`.local/wslc-validation/<utc>-<guid>/{work,evidence,result.json}`).


## Product-path integration (PR-29)

Recorded 2026-10-06 · PR-29 working tree · same reference host (Windows
11 25H2 26200.9457 x86-64, interactive session, WSL **3.0.1.0** /
`wslc` client 3.0.1.0, kernel 6.18.40.1-1, distros `Ubuntu` +
`docker-desktop`).

PR-28's "adoptable as an ordinary container substrate" decision is now
wired: `--engine wslc` is an *explicit-selection* engine on the default
`container` isolation. It is never auto-detected, never aliased to
`container.exe`, and never a silent substitute for docker/podman.

### What the product path does

- **Resolution**: `WslcEngine` resolves `wslc` as
  `MCP_WRIT_WSLC_EXE` → PATH → `C:\Program Files\WSL\wslc.exe` (the
  stock install does not export PATH; the reference host resolves via
  the install dir). The version gate parses `wslc --version`'s
  *validated* line only — unrecognized layouts stay unverified — and
  requires WSL product ≥ 2.9.3 (`wsl.exe --version`). The version
  probe is bounded (5 s, kill-on-timeout) — `resolve_engine`/
  `is_available` are sync callers, so a wedged CLI is killed rather
  than stalling `run-image`/`plan`/`wrap-image`; the same bound now
  guards every engine's `is_available`.
- **Launch**: `wslc run -i --rm --pull never --name
  mcp-writ-wslc-<12hex>` plus the shared OCI contract (`--entrypoint`,
  `-e`, `--cidfile`, mounts). Session warm-up is `wslc system session
  run /bin/true` once per launch when no `wslc-cli-*` session is listed
  — it materializes the session VM in the session's *own* rootfs, so no
  image, no container entrypoint, and no unit is created (verified on
  wslc 3.0.1.0: ~2 s cold, the session lists afterwards; a timed-out
  client leaves nothing to reap). The first workload's stdio then
  carries no session provisioning chatter. `--pull never` hardens
  against an accidental registry fetch; image presence is verified by
  `image inspect` beforehand.
- **Untrusted exit codes**: `wslc` CLI errors can exit 0 — `inspect`,
  `image inspect`, and `rm` results are validated by stderr content and
  JSON shape (measured: a missing image prints a localized error on
  stderr with exit 0; the engine maps it to `CommandFailed`).
- **Lifecycle**: `EngineRunHandle` addresses the unit by the
  `--cidfile`-recorded id — verified on wslc 3.0.1.0 that the id file
  carries the full hex container id and `wslc inspect`/`kill`/`rm -f`
  accept it directly (an unknown id answers
  `WSLC_E_CONTAINER_NOT_FOUND`; no name fallback needed). Termination
  sends `wslc kill -s SIGINT <unit>` first (SIGINT unwinds the runner —
  the substrate's own graceful path; whether it ends the unit is the
  init's signal disposition, same as docker) and `wslc rm -f` is
  idempotent cleanup. The shared session VM is *not* owned by the
  launch and is left running.
- **Report identity**: `engine=wslc`, `substrate=container`,
  `unit=container`, `unit_id=<cidfile>`,
  `detail="engine: wslc (shared session VM — substrate plumbing,
  unit=container)"` — the session VM is never reported as a VM
  isolation boundary.
- **Scope gates**: linux/amd64 images only (foreign arches and Windows
  guests refuse before launch); `build` (`wrap-image`/`containerize`)
  goes through `ContainerEngine::build` (`wslc build -f/-t/--no-cache`)
  and verifies the produced image with `image inspect` — the CLI's
  exit-0 error dialect means the image materializing is the success
  fact. `--engine wslc` paired with a non-`container` isolation refuses
  at engine resolution (`engine_kind_applies` gates it in
  `resolve_launch_engine` and `plan`'s `engine.resolve`) rather than
  resolving and failing a later check. `plan --engine wslc` emits
  `wsl.*`/`wslc.*` checks only under `container` isolation and keeps
  `wslc.runtime` `skipped` (no session start, no pull, no update, no
  elevation).

### Product legs (asserted, `tests/wslc_container_e2e/product.rs`)

| Leg | Asserted |
|---|---|
| `wslc_product_run_image` | `run-image --engine wslc` → initialize + `tools/call` round-trip over `wslc run -i` stdio; report records `engine=wslc`, `configured=verified=container`, `unit=container`, shared-session detail, guest report `state=received` (`guest-report-1`), `result.status=exited` code 0; no `mcp-writ-wslc-*` unit left listed |
| `wslc_product_refuses_unwrapped_image` | an image without the `mcp-secure-runner` entrypoint refuses naming the contract, exits nonzero, still writes the launch report, leaves no unit |
| `wslc_product_external_sigint_ends_session` | the owned unit's name lists on `wslc list`; external `wslc kill -s SIGINT <unit>` is accepted → guest runner logs `Received SIGINT, forwarding to child` / `child terminated by signal 2`, the client exits, the unit is reaped, the session survives |
| `wslc_product_plan_diagnostics` | `plan --engine wslc` reports `engine.resolve`/`wslc.cli`/`engine.locality`/`runner.entrypoint` `pass`, `engine=wslc`, `substrate=container` |

Manually verified on the same host beyond the legs: `plan` on a missing
policy reports `blocked`/`policy_not_found` (engine resolution still
`pass`); `image inspect` of an absent tag fails through stderr
detection despite the CLI's exit-0 quirk; an unwritable `--report`
path refuses before any engine call.

The full gated suite was executed on the reference host after the
PR-29 review remediation (bounded CLI probes, `system session run`
warm-up, trait-routed `build`, `--engine wslc` × non-`container`
refusal at resolve): `MCP_WRIT_REQUIRE_WSLC_TESTS=1 cargo test
--locked --test wslc_container_e2e` → **16/16 passed, 0 skipped**
(~70 s, evidence under `target/wslc-evidence/run-pr29/`). The run
surfaced one harness defect — interactive launches spawned a bare
`"wslc"` (PATH-only) while the stock install exports no PATH; all
spawn sites now resolve through `wslc_prog()`.

### Harness note

`tests/wslc_container_e2e/support.rs::wslc_prog` resolves `wslc` with
the product's own precedence (`MCP_WRIT_WSLC_EXE` → PATH → install
dir), and every spawn — one-shot probes *and* interactive `run`
sessions — goes through it, so the suite no longer requires the PATH
augmentation `scripts/validate-wslc.ps1` performs — the script's
prepend remains harmless.

### Still out of scope (unchanged from PR-28)

Dedicated per-workload sessions (`--session`/`enter`), SDK calls,
enterprise policy/Intune, MDE plug-in, ARM64, elevated sessions,
Windows-container workloads, `wslc run -d` detach, `-p` publish in the
product launch contract. Re-verify per the [version-bump
axes](#version-bump-reevaluation-axes-per-pr-28) when the baseline
moves.
