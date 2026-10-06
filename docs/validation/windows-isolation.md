# Windows isolation mechanisms — comparison & real-machine evidence (PR-30)

Real-machine verification for the PR-30 question: can **Win32 app
isolation**, **PSEC** (ProcessSecurityEnvironment), **IsolationSession**,
or **MXC** improve on the shipping AppContainer + LPAC + Job Object +
DACL path — measured against mcp-writ's actual policy surface.

Scope discipline: **this PR compares and verifies only.** Nothing here
connects a new mechanism to the product launch path — `mcp-writ run`'s
Windows engine decision is unchanged (PR-31's job, gated on this doc's
adoption conditions), no preview/Insider feature was enabled on the
validation host, and no candidate is presented as "supported" from
PR-30 evidence alone.

Status: **measured on the reference host — `winiso-tests-passed`** —
recorded 2026-10-06 · commit `a10b7bb` · Windows 11 Business
26200.9457 (25H2, retail — `insider:false`) x86-64, session 1,
non-elevated (integrity 8192), rustc 1.99.0. Evidence bundle:
`.local/winiso-validation/20261006-125656-48c07f26a0bb46a8a8185b9f3f601977/`
(probe leg JSONs under `evidence/`, e2e output under `evidence/e2e/`,
hashes in `result.json`); prior battery under `.local/winiso/`.
See [Verdicts](#verdicts-pr-30).

## The probe fixture

`tests/fixtures/windows_isolation/winiso_probe.rs` — a single std-only
Windows binary (`rustc --edition 2021 -O`, no crates, no import libs;
`raw-dylib` + runtime `LoadLibraryExW`/`GetProcAddress` only) with
bounded waits and one JSON line per mode:

| mode | what it does | evidence tier |
|---|---|---|
| `facts` | OS build/display version/edition/arch, token facts (session, elevation type, IL), presence + version of the candidate binaries/services/API sets | presence |
| `contracts` | PSEC: API-set impl flags, `processmodel.dll` export resolution, `QueryProcessSecurityEnvironmentSupport`, `IsProcessSecurityEnvironmentVersionSupported` 1.x/2.x, malformed-spec HRESULTs. IsolationSession: per-DLL exports + WinRT activation (`IsoSessionOps`, `Preview.IsoSessionOps`, `IsoStationOps`, plus a `NotARealClass` negative control). Win32 app isolation: service presence only. | contract answers |
| `attempts` | the attempt battery *in whatever context runs it*: fs read/write/enumerate on granted/denied/ungranted dirs, `WSAStartup` + raw Winsock connects to an allow-listed listener port vs denied ports/destinations, HKLM/HKCU writes, named mutex, (grand)child spawn, env-var visibility, token facts | measured attempts |
| `ac-run` | full shipping path — `CreateAppContainerProfile`, DACL grant/restore on RO+RW dirs, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (+LPAC on `--lpac`, internetClient SID on `--net`), `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, Job `KILL_ON_JOB_CLOSE`, `DeleteAppContainerProfile`. `--image <exe> <argv>` spawns an external binary instead of the self-`attempts` child — the interpreter launch legs | enforcement + cleanup |
| `psec-run --ro D --rw D --deny D` | hand-built FlatBuffers `PSEC` spec (schema v1.0) → `CreateProcessSecurityEnvironment` → child spawned with `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` → same battery → `CloseProcessSecurityEnvironment`; egress policy pinned to the wrapper's listener port. `--image` swaps the child as above | enforcement + cleanup |
| `psec-spec-test` | create/close ladder over spec variants (minimal v1.0/v1.1, no-identifier, each field alone, nested deny, `C:\` deny, allow-rule, full) | schema acceptance |
| `sleep <ms>`, `spec-file`, `attempts` flags | plumbing for the grandchild leg and spec inspection | — |

Context reaches the child on **argv** (`--ro/--rw/--deny/…`), not env —
that choice is itself evidence (see PSEC below).

## Baseline: AppContainer + LPAC + Job + DACL (shipping path)

`src/warden/windows_sandbox.rs` + `windows_profile.rs` +
`windows_proc.rs`: named profile → per-path DACL ACEs
(read/write/deny) → `SECURITY_CAPABILITIES` (LPAC adds
`PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`; capabilities
SIDs on request) → `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` for stdio
pipes → Job `KILL_ON_JOB_CLOSE` → `DeleteAppContainerProfile` + ACL
restore on exit.

Measured on the reference host (`evidence/ac-run.json`, `-net`, `-lpac`
variants):

- `is_appcontainer=true`, IL 4096, per-run package SID; host IL 8192.
- fs: RO-read ok / RO-write `err:5` / RW-write ok / deny-dir read+write
  `err:5` / ungranted read `err:5` / enumerate ok.
- net: `WSAStartup` ok; closed-port connect `WSAECONNREFUSED(10061)` —
  the AC child *reaches* the loopback stack; a host-owned listening
  port times out (loopback isolation is orthogonal to capabilities —
  `ac-run --net` with `internetClient` still times out; the
  `CheckNetIsolation LoopbackExempt` path is the documented escape and
  was not touched — it mutates host state).
- LPAC: `WSAStartup` → **10107 (WSASYSCALLFAILURE — provider init is
  denied, so all sockets are dead, not just denied connects)** and
  `spawn_grandchild` → `err:5` (LPAC blocks child-process creation
  outright).
- tree: `spawn_grandchild` ok → `gc_killed=true` on job close.
- **unpackaged interpreter launch** (`ac-node.json`): `node.exe` v24
  spawned under the token straight from `C:\Program Files\nodejs`
  (no DACL grant on it — the AC default read set covers Program
  Files) and a marker reached stdout through the same inherited-pipe
  plumbing MCP stdio uses; a staged copy inside the RW grant works
  equally. The shipping path keeps supporting Node/Python-class
  servers — the precondition every candidate is compared against.
- cleanup: every grant `applied+restored`, `profile_deleted=true`,
  `cleanup_error=false`; the run's SIDs absent from
  `…\AppContainer\Mappings` afterwards.

## Win32 app isolation — verdict: 保留 (feature absent on this host)

Facts (`facts.json`, `contracts.json`): `api-win-app-isolation-l1-1-0`
**not implemented**, `appisolation.dll` absent, `appisolation` service
unregistered on the 25H2 retail host. The packaging/capability/consent
contract (MSIX manifest + `runFullTrust`-adjacent capabilities + consent
prompts) is documented Microsoft surface, but:

- it requires a **packaged** identity — unpackaged Node/Python MCP
  servers are outside the model;
- consent UX is aimed at interactive use — a non-interactive stdio
  launch path needs its own verification on a host that has the feature;
- capability names are not evidence of coverage of the current policy
  rows (per-path deny granularity, destination/port egress rules are
  not expressed by the documented capability set).

Nothing enforceable was measurable here → **hold**, with the unblock
condition "a shipping build with `api-win-app-isolation` implemented
plus a packaged-server and consent evaluation". Not "rejected": absence
of the feature on one build is not proof the mechanism can't work.

## PSEC — verdict: 条件付き (conditional)

The discovery that shaped this leg: the 25H2 **retail** host ships
`processmodel.dll` + the full export set + the
`api-win-appmodel-processmodel~securityenvironment` API set, and the
contract answers `v1.0 available` — the presence table MXC publishes
("no processmodel.dll before Insider") is not accurate for this build,
which is exactly why the probe measures rather than trusts.

Measured (`contracts.json`, `psec-spec.json`, `psec.json`):

- exports: all 12 resolved (`CreateProcessSecurityEnvironment`,
  `QueryProcessSecurityEnvironmentSupport`,
  `IsProcessSecurityEnvironmentVersionSupported`,
  `CloseProcessSecurityEnvironment`, the `LearningModeTrace` trio,
  `CancelProcessSecurityEnvironmentTerminateOnClose`,
  `SbeGetSecurityEnvironmentAppContainerSid`, the `Experimental_*`
  sandbox trio).
- `QueryProcessSecurityEnvironmentSupport` → `hr=0x0`,
  `flags=0x0000000000000003` (bit 0 = FileSystemDeny present; the v1.1
  `fs_enumerate`/`network ingress` bits are clear — consistent with the
  version answer).
- versions: `1.x` → `available=true` (minor 0); `2.x` → not available.
- spec ladder: `minimal-ident-v1.0` ok; `minimal-ident-v1.1` →
  **`0x80070032` (not supported)**; missing `PSEC` identifier →
  `0x8007000d`; every v1.0 field shape — fs ro/rw/deny alone, nested +
  `C:\` deny, deny-all egress, pinned allow rule, full spec — created
  and closed cleanly.
- `psec-run` (RO+RW+deny dirs + egress `default deny` + one pinned
  `127.0.0.1:<listener>` allow rule):
  - child gets an **AppContainer-derived token** (fresh package SID per
    run, IL 4096) — PSEC layers on app-container machinery;
  - fs: RO-read ok / RO-write `err:5` / RW-write ok / deny r+w `err:5` /
    ungranted `err:5` (default-deny) / enumerate ok;
  - egress: same-host other-port and different-destination both
    `WSAEACCES(10013)` — **the policy layer refuses, distinguishable
    from AC's `10061` answer**; the pinned allow connect passed the
    policy filter and then timed out on the loopback-isolation layer
    (same behavior AC shows — PSEC's egress allow does not confer the
    NetworkIsolation loopback exemption);
  - `WSAStartup` ok (PSEC is *not* LPAC — sockets exist; policy decides
    per-connect);
  - grandchild spawn from a granted-path exe → ok, `gc_killed=true` on
    the parent Job — **process-tree termination works with the
    mechanism, not around it**;
  - **env block is not inherited** (`env_seen` all false) — a PSEC
    child starts with a fresh environment. This is a real compatibility
    constraint: env-var-configured MCP servers (API keys, paths) break
    unless the runner passes config by argv/file. Recorded, not worked
    around;
  - **unpackaged interpreter launch** (`psec-node.json`): `node.exe`
    spawned through the security environment and printed its marker —
    with the install dir in `fs_read_only` *and* with no grant on it at
    all (the PSEC fs lists are deltas on the AppContainer-derived base,
    which already covers Program Files). So `node -e` survives PSEC;
    env-dependent configuration still does not (row above);
  - stdio pipes work (the child's JSON arrived over the inherited
    pipe);
  - cleanup: `env_closed=true`, and the run's SIDs leave **no**
    `AppContainer\Mappings` residue — the environment is its own
    lifetime, no named-profile lifecycle to leak.

Remaining gaps (why Conditional, not Adoptable):

- the wire contract is public only through the **MXC preview SDK's
  `ProcessSecurityEnvironment.fbs`** — no documented Microsoft header/
  IDL guarantees stability; `0x80070032` on v1.1 shows the contract
  *does* move;
- one host build verified (26200.9457); 24H2, earlier 25H2, Server,
  ARM64, Insider deltas unverified;
- `network ingress`, `fs_enumerate`, `capabilities` string,
  `ui_restrictions`, `disallow_win32k` are v1.1-or-unprobed surface;
- registry/named-object/atomic-rename semantics under PSEC inherit the
  AC layer's behavior — measured only for the legs above;
- the audit surface (LearningModeTrace) is export-present but unexercised.

Adoption conditions for PR-31: multi-build runtime probe pass (the
fixture's `contracts`+`psec-run` legs are the acceptance shape), a
supported-contract statement from Microsoft for v1.0, an env-passing
design (argv/config file), and fallback policy that refuses when a
required policy row can't be expressed.

## IsolationSession — verdict: 保留 (Insider/preview, lifecycle unverified)

Measured (`contracts.json`, `facts.json`): `IsoSession{App,Cli,Client,
Server,ProxyStub}` binaries present; `IsoEnvBroker` + `IsolationSession`
services registered (manual, stopped — the probe never starts them);
all three WinRT factories **activate** on retail — `IsoSessionOps`
(18 IIDs), `Preview.IsoSessionOps` (3), `IsoStationOps` (1) — with the
`NotARealClass` control failing `0x80040154`, so activation is real.

But activation ≠ contract: the session-lifecycle surface (create under
another user, folder sharing, non-TTY stdio, termination, registration/
unregistration, cleanup) lives behind a **private WinMD** in MXC's
Insider builds; none of it was measurable without reverse-engineering a
preview API on a retail host — out of scope, and the lab leg is gated
(`-Lab`) rather than half-run. **Hold** until a dedicated Insider
environment exercises the full lifecycle; "user-session separation" is
never relabeled VM separation.

## MXC — verdict: 保留 / 条件付き, split in two

- **MXC-SDK route**: the SDK is explicitly early-preview, its profile
  vocabulary (`--profile` configs) is a convenience layer, **not** a
  security boundary to adopt, and `bfscfg.exe`/`bfssvc` (the BFS path
  MXC disables in favor of SBE/PSEC) are registered-but-absent on this
  host (`bfscfg.exe` present in System32, `bfssvc` unregistered — never
  started). Depending on the SDK moves Microsoft's preview support
  window into our dependency graph → **hold**.
- **OS-direct route** (what the fixture already proves is possible):
  `LoadLibrary` + PSEC + security-environment attribute needs no MXC
  runtime at all — it inherits the PSEC verdict above (**conditional**),
  with the same unversioned-contract caveat. The MXC source remains the
  best public documentation of the schema — reference material, not a
  dependency.

## Comparison table (vs the AppContainer baseline)

`measured` = asserted on the reference host; `contract` = documented
surface only; `—` = not applicable / not evidenced.

| row | AppContainer+Job+DACL (baseline) | Win32 app isolation | PSEC | IsolationSession | MXC (SDK) |
|---|---|---|---|---|---|
| file read / write / deny per path | **measured** (DACL) | contract (capability-broad) | **measured** (ro/rw/deny lists, default-deny) | unverified | inherits PSEC |
| file enumerate | measured (RO) | contract | deny-by-default measured; explicit list is v1.1 (`0x80070032`) | unverified | inherits |
| network direction/port/destination | no egress control measured; loopback isolated; `internetClient` capability gates WNF-class traffic | contract (capabilities, no port/dest rules) | **measured**: egress deny = 10013, dest+port allow-rule evaluated; ingress = v1.1 | unverified | inherits |
| process tree stop | measured (Job kill-on-close, grandchild dead) | packaged-model only | measured (Job composes) | session terminate unverified | inherits |
| stdio pipes | measured | non-interactive path unverified | measured (inherited pipe) | non-TTY unverified | inherits |
| registry | HKLM/HKCU write denied (measured) | virtualized (contract) | denied — same AC layer (measured) | unverified | inherits |
| named objects | `Local\` mutex ok (measured) | contract | ok (measured) | unverified | inherits |
| child spawn inside boundary | measured | n/a (LPAC-like limits possible) | measured ok from granted path | unverified | inherits |
| unpackaged interpreter launch (Node) | **measured** (`node -e` marker over stdio pipe, direct + staged copy) | unpackaged servers are outside the model | **measured** (image grant optional — fs lists are deltas on the AC base; env config still absent) | unverified | inherits |
| env inheritance | **yes** (measured) | packaged env rules | **no** (measured — config must ride argv/files) | unverified | inherits |
| required privileges | none (non-elevated works) | packaging + consent | none measured | broker service (manual) untested | broker/services |
| packaging/distribution | none | MSIX package required | none | Insider/private WinMD | preview SDK |
| update/servicing | in-box, stable API | ships in-box (feature-gated) | unversioned — `0x80070032` proves it moves | Insider-channel | preview SDK |
| cleanup/rollback | profile delete + ACL restore measured | package unregister | env close, no residue (measured) | unverified | inherits |
| ownership (user/session/package/ACL) | per-user profile, caller-owned ACLs | package/user | per-env anonymous SID | per-user session, other-user create untested | profiles ≠ boundary |
| audit/observability | none native (audit is ours) | contract (audit events) | LearningModeTrace exports present, unexercised | unverified | SDK events |
| policy expressiveness | fs rw/ro/deny + caps + LPAC | capability names only | fs rw/ro/deny + egress dest/port (v1.0) | unknown | whatever PSEC does |

## Reproduction

```powershell
# Full validation run (writes .local\winiso-validation\<run>\result.json):
powershell -File scripts\validate-windows-isolation.ps1
# Insider lab legs (not implemented — lifecycle needs the private WinMD):
powershell -File scripts\validate-windows-isolation.ps1 -Lab
# Legs by hand:
rustc --edition 2021 -O -o winiso_probe.exe tests\fixtures\windows_isolation\winiso_probe.rs
.\winiso_probe.exe facts; .\winiso_probe.exe contracts; .\winiso_probe.exe psec-spec-test
# (set WINISO_*_DIR then) .\winiso_probe.exe ac-run / psec-run --ro D --rw D --deny D
# External-image legs (unpackaged interpreter under the same token):
.\winiso_probe.exe ac-run --image "C:\Program Files\nodejs\node.exe" -e "console.log('node-ac-ok')"
.\winiso_probe.exe psec-run --ro D --rw D --deny D --image "C:\Program Files\nodejs\node.exe" -e "console.log('node-psec-ok')"
```

The e2e (`cargo test --locked --test windows_isolation_e2e`) runs the
golden contract layer anywhere; the live legs run on Windows when rustc
is available and turn prerequisite skips into failures under
`MCP_WRIT_REQUIRE_WINISO_TESTS=1` (the validate script sets it).

## Unverified axes (recorded, not claimed)

- OS: only 26200.9457 (25H2 retail) x86-64 Professional/Business-class
  measured. 24H2, LTSC, Server, ARM64, any Insider build: unverified.
- Privilege: non-elevated only. Session 0 / service context: unverified
  (script gates on interactive session).
- PSEC: `capabilities` string, `ui_restrictions`, `disallow_win32k`,
  ingress policy, `fs_enumerate`, LearningModeTrace audit records,
  behaviors when the spec is *too strict* to launch (e.g. denying the
  exe's own directory) — all unprobed.
- AC: external (non-loopback) egress policy — `internetClient` leg was
  loopback-only on this host.
- IsolationSession: everything past activation is unverified by design
  (lab-gated).
- The `detail` strings in leg JSON are OS-localized (JP host) —
  classification keys on `result` codes, never on `detail` text.

## Cleanup & rollback contract

The fixture creates only: `mcp-writ-pr30-*` AppContainer profiles
(deleted in-leg; the validate script diffs the `Mappings` hive before/
after and fails on residue), DACL ACEs it records and restores, dirs
under the run's `work/` (removed in `finally`, path-guarded), PSEC envs
(closed in-leg), and the Job/child processes (kill-on-close verified).
The validate script additionally restores every `WINISO_*`/`TEMP` env
var it set and leaves only `evidence/` + `result.json`. Nothing was
installed, enabled, or registered on the host: `insider:false`,
`bfssvc`/`appisolation` unregistered before and after.

## Verdicts (PR-30)

| candidate | verdict | improvement over baseline | binding constraint |
|---|---|---|---|
| AppContainer+Job+DACL | **baseline** (unchanged shipping path) | — | — |
| Win32 app isolation | **hold** | none measurable | feature absent on retail 26200; packaging+consent model unverified for stdio servers |
| PSEC (OS-direct) | **conditional** | real egress dest/port policy; fs deny without DACL bookkeeping; self-cleaning env | v1.0-only wire contract is preview-documented; env not inherited; multi-build unverified |
| IsolationSession | **hold** | distinct-user session model | private WinMD / Insider lifecycle unexercised |
| MXC SDK | **hold** | schema documentation value | early preview; profiles are not a boundary; SDK support window |

PR-31 entry condition: a candidate reaching *adoptable* needs (a) a
supported public contract or a stability commitment, (b) the fixture's
contract+run legs green on the support floor builds, (c) the
env-inheritance gap designed around, (d) deny-fallback refusal wired.
On this evidence set, **no candidate is adoptable; PSEC is the
conditional front-runner**; PR-30 therefore ends as "evaluated — none
adopted", which is a complete result, not an implementation claim.
