# Successor mechanisms & new ABIs — investigation record (improvement plan PR-11)

Investigation-only PR per `docs/improvement-pr-guide-2026-11.ja.md` PR-11.
Reassesses the successor mechanisms and new ABIs named by evaluation
report R-02 after the 2026-10-07 MXC GA, and checks whether they can
close OS-level capability gaps while the shipping sandboxes stay in
place. **Nothing here wires a new mechanism into the launch path** —
the product `run`/`plan` engine decision is unchanged and no candidate
is presented as supported from this evidence alone.

Status: **investigation complete — see per-target verdicts** — recorded
2026-11-07 · working tree · two measurement hosts:

- **Windows**: Windows 11 Pro 26200.9711 (25H2, retail) x86-64,
  session 1, non-elevated (IL 8192), `mxc-sdk` crate 1.0.1
  (crates.io, 2026-10-17, MIT), rustc stable. Evidence bundle:
  `.local/pr11-mxc/` (probe outputs; scratch probe sources under
  `%TEMP%\mxc-probe`, fixture copy under `%TEMP%\winiso-copy`).
- **Linux**: WSL2 on the same host, Ubuntu 24.04.2, kernel
  `6.18.54.1-microsoft-standard-WSL2`, x86-64.
- **macOS**: no probe possible (no macOS 27 host, entitlement not
  held) — documentation research only, marked **unverified**.

## Capability-matrix mapping (all targets)

Per the PR-11 task, each mechanism's expressible controls are mapped to
the matrix axes before any verdict. `—` = no hook exists.

| axis | MXC ProcessContainer (tier 1, measured) | ES `es_new_descendants_client` (docs) | Landlock v10/v11 (docs + ABI probe) |
|---|---|---|---|
| fs | `readonly_paths`/`readwrite_paths`/`denied_paths`/`enumerate_paths` — default-deny, measured enforced (ro-write/deny/ungranted → `err:5`) | auth events for open/mutation across the descendant subtree | fs rights unchanged since v9 (UDP/net only in v10); fs is not the delta |
| network destination | egress `default` + `allow[]`/`deny[]` of `cidr`+`protocol`+`port` — measured enforced on non-loopback (deny → `WSAEACCES 10013`); **loopback is exempt from egress rules — gated only by `ingress.host_loopback` (all-or-nothing)** | **no authorization event for IP networking** — cannot express allow/deny | v10 `LANDLOCK_ACCESS_NET_BIND_UDP` + `CONNECT_SEND_UDP` — **port-scoped only, never address-scoped** (same model as TCP since v4) |
| syscall | container-side seccomp surface is OS-managed; no caller knob measured | — | — (orthogonal; warden's seccomp baseline stays regardless) |
| IPC | named objects: `Local\` mutex creation measured `ok` | auth for unix-domain IPC + macOS-27 XPC/bootstrap ops | v6 scoping (abstract unix, signals) already ≥ our baseline; v9 named-unix connect is the last relevant item (already handled) |
| process | grandchild spawn measured `ok`, inherits the container (job-managed tree) | auth for exec/process controls; caller+descendants **cannot exec setuid/setgid** unless euid 0 | v8 `TSYNC` (process-wide enforce) / v11 `NO_NEW_PRIVS` flag — cosmetic for our child-launch model (already `prctl`) |
| audit/observability | `CaptureDenials` capability advertised (Learning Mode) — **unverified** what it emits | notify+auth events for the whole subtree — strong observability within scope | v7 audit logging, v10 quiet flag, v11 tracepoints — audit-relevant deltas worth tracking |

## Target 1 — Windows MXC, GA reassessment

Re-run of the PR-30 question against the shipped SDK (`v1::run`,
`v1::spawn`, `Containment::Process` — resolves to the ProcessContainer
backend).

### Contract/presence re-measure (this host vs PR-30's 26200.9457)

- `platform_support()`: `is_supported=true`, `available_methods=["processcontainer"]`.
- `available_backends()`: `processcontainer` tier `base-container` with
  capabilities `[CaptureDenials, FilesystemDeniedPaths,
  FilesystemEnumeratePaths, IngressHostLoopbackAllow,
  IdentitylessLoopbackProxy]`; `windows_sandbox` listed with empty
  capabilities (lifecycle daemon model, not exercised).
- PSEC surface grew since PR-30: `QueryProcessSecurityEnvironmentSupport`
  flags `0x3 → 0xf` (v1.1 `fs_enumerate` + `network ingress` bits),
  `IsProcessSecurityEnvironmentVersionSupported` v1 minor `0 → 1`, the
  Learning Mode API set is now implemented. The wire contract is no
  longer preview-only: the SDK builds and submits it in-process.
- Backend tiers (crate source `fallback_detector.rs`): **tier 1 =
  BaseContainer (PSEC)** — what ran here, unprivileged; tier 2 =
  AppContainer + `bfscfg` BFS (cargo feature `tier2_bfs`, needs elevated
  `wxc-host-prep` mutations); tier 3 = AppContainer + DACL (host-prep
  too). Tiers 2/3 were **not exercised** (elevation out of probe scope).
- `Containment::IsolationSession` also exists behind the crate's
  `isolation_session` cargo feature — not exercised (feature off, and
  PR-30's hold stands: session lifecycle still needs the dedicated lab).
  `windows_sandbox` appears in `available_backends` with empty
  capabilities.

### Measured behavior inside the container (winiso `attempts` battery)

- Token: `is_appcontainer=true`, IL 4096, per-run AppContainer SID —
  confirms BaseContainer layers on app-container machinery (same as
  PR-30's PSEC child).
- fs: `ro` read ok / write `err:5`; `rw` write ok; `denied` +
  `ungranted` read+write `err:5`; enumerate of granted dir ok.
- **env**: SDK `environment` map is delivered verbatim — `WINISO_RO_DIR`
  seen `true` inside the child. This closes PR-30's PSEC gap ("env
  block is not inherited") at the SDK contract level: `Some(vec)` is
  verbatim, `None` = backend default, `Some(vec![])` = empty.
- egress: `default deny` + `allow {to cidr, port P}` verified in both
  directions — off-rule non-loopback `203.0.113.1:443` → `WSAEACCES
  10013`; a non-loopback allowed destination+port (host LAN IP
  `172.21.240.1:59111`, listener on `0.0.0.0`) → **connected**. CIDR+port
  rules are enforced as documented for non-loopback destinations.
- **loopback anomaly (security-relevant)**: with
  `ingress.host_loopback=Allow`, a loopback port *outside* the egress
  allow rule **still connected** — host loopback is governed solely by
  the all-or-nothing `host_loopback` bit, not by egress CIDR/port rules.
  With `host_loopback=Deny` both loopback connects → `WSAEACCES`.
  For the direct-egress path measured here, warden policies that allow
  a specific `127.0.0.1:port` (the warden-proxy pattern) get no port
  scoping — allowing loopback opens all of it. Whether the
  `runtimeConfig.networkProxy` HTTP/S-proxy route (or the
  `IdentitylessLoopbackProxy` capability) can scope egress more finely
  was **not probed** — treat proxy-mediated scoping as unverified, not
  proven impossible.
- stdio/lifecycle: `spawn()` gives live `stdin/stdout/stderr`
  `Box<dyn Read/Write>` pipes, `id()`, `kill()`, `wait()` — sufficient
  for the MCP stdio contract. `take_native_stdio()` must be called
  before individual `take_*` streams (ordering quirk).
- registry/objects/tree: HKLM+HKCU writes `err:5`; `Local\` mutex ok;
  grandchild spawn ok and inherits the container.

### Blocking defect found — `ole32.dll` cannot initialize in tier 1

- A child image that **imports `ole32.dll` exits `0xC0000142`
  (`STATUS_DLL_INIT_FAILED`) before `main`**, with or without
  fs/network policy, with default or custom env, from granted or
  ungranted dirs.
- Bisect: minimal Rust exe ok; `userenv`/`ws2_32`/`advapi32`/
  `kernelbase`/`version`/`combase` linked exes ok; **`ole32`-linked exe
  fails**. `combase` COM works (`CoInitializeEx` → `S_OK`) — the
  failure is specific to ole32's DLL init inside this container type.
- Real-world check: **`node.exe` (v24, `C:\Program Files\nodejs`)
  imports `ole32.dll` → cannot launch in the tier-1 container**
  (`0xC0000142`, evidence `node-fail.txt`). `python.exe` (3.12, no ole32
  import) runs fine once its install dir is granted `ro` → `PY_MXC_OK`.
- Impact: the dominant MCP server runtime (Node) is unlaunchable in the
  measured tier. Whether tier 2/3 (AppContainer+BFS/DACL) avoids this is
  **unverified** — they need elevated host preparation that this
  non-elevated probe could not perform.

### Verdict — **hold (conditional candidate)**

Do not adopt as a warden mechanism yet. Start conditions for a
follow-up PR:

1. `ole32`-init failure resolved — an OS build where Node-class images
   start in tier 1, **or** a tier-2/3 fallback verified non-elevated,
   **or** a documented opt-in accepting "no ole32-importing children".
2. Policy mapping decided for the loopback model: warden per-dest
   `127.0.0.1:port` allows cannot be expressed (all-or-nothing
   `host_loopback`). Acceptable only for policies that deny loopback
   wholesale.
3. Launch-cost measured (per-run container create) and audit story
   verified (`CaptureDenials`/Learning Mode output).
4. If adopted: coexistence with the shipping AppContainer+DACL+LPAC
   path as a separate engine selection — never a silent substitute.
   MXC subsumes our hand-rolled PSEC spec builder if adopted.

## Target 2 — macOS ES `es_new_descendants_client` (macOS 27+)

Documentation research only — **unverified** on real hardware (no
macOS 27 host; the entitlement is not held).

Facts from Apple's API reference + developer docs:

- New in **macOS 27**. Creates an ES client scoped to the calling
  process's **entire descendant subtree** (existing + future,
  recursive). The caller gets notify events; descendants get
  auth+notify. Process/path/target-path muting works within the subtree.
- Requires `com.apple.developer.endpoint-security.client` — an
  Apple-granted entitlement (exists since 10.15; historically issued
  mainly to security vendors — real distribution risk for a
  general-purpose CLI). **No root, no TCC** — that is the genuinely new
  part vs classic ES.
- Caller and descendants cannot exec setuid/setgid binaries unless
  euid 0 (blocked execs produce no exec event).
- Coverage: auth events for exec, file open/mutation, process controls,
  IOKit, unix-domain IPC, and macOS-27 XPC/bootstrap ops. **There is no
  authorization event for IP networking** — outbound/inbound allow-deny,
  the core of warden's contract, cannot be expressed. Notify-only
  events give visibility, not enforcement.

### Verdict — **declined (as an enforcement mechanism)**

Cannot express network policy, so it can never be a standalone warden
mechanism. It could complement Seatbelt as descendant-scoped
*audit/auxiliary* control — but a hard entitlement + audit-only value
does not justify a dependency yet. Revisit only if Apple adds network
authorization events or warden's macOS contract changes shape. OpenAI's
codex evaluation (#38028) reached the same coverage conclusion
independently.

## Target 3 — Linux Landlock ABI v10/v11

Mixed: real ABI probe + crate/kernel documentation.

### Measured

- WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`:
  `landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)` →
  **ABI 7**. Kernel version ≠ ABI — always probe the syscall (matches
  `src/warden/landlock_impl.rs::kernel_abi`).
- Repo pins `landlock = "0.4.7"` (`Cargo.toml`/`Cargo.lock`) — exposes
  ≤ **ABI 9**; upstream ABI-10 support is tracked
  (rust-landlock#140), not released → **even on a 7.2+ kernel the UDP
  rights are inexpressible through the current dependency**.

### Documentation (landlock.io/kernel docs ABI table)

| ABI | kernel | delta relevant to warden |
|---|---|---|
| v8 | 7.0 | `restrict_self` `TSYNC` — process-wide enforcement; irrelevant to our child launch |
| v9 | 7.1 | named unix-domain connect control — already consumed (`ResolveUnix`) |
| v10 | 7.2 | **UDP port control** `BIND_UDP` + `CONNECT_SEND_UDP` (bind/connect/send, port-scoped — **never address-scoped**) + audit quiet flag |
| v11 | 7.3 | tracepoints; `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` — we already `prctl` |

What v10 would buy: under `deny_all_others`, UDP is currently killed at
the socket-family level by the seccomp baseline and *any* UDP allow is
dead policy for native (`select.rs` refuses). v10 could express
**host-agnostic** UDP port grants — but warden policies are
destination-scoped (`host`+`proto`+`port`), and Landlock has no address
concept at any ABI. So destination-scoped UDP still needs the
namespaced route; v10 only helps policies that allow a UDP port for
*any* host — a marginal posture gain, plus the kernel note that
auto-bind needs `BIND_UDP` on port 0 or a pre-bound socket.

### Verdict — **hold**

Unblock conditions: (a) a `landlock` crate release exposing ABI ≥10
(or an in-tree uapi implementation); (b) re-evaluate on a host kernel
≥7.2 — the current reference host reports ABI 7; (c) adoption limited
to host-agnostic UDP port grants; destination rules stay namespaced;
(d) capability matrix updated **only at adoption** — no matrix change
from this investigation. v11 tracepoints/quiet flag are audit-relevant
watch items, not enforcement gains.

## Target 4 — Ubuntu 24.04+ unprivileged-userns restriction vs `auto`

Code-verified + documentation; environment restriction not reproducible
on the WSL host (and intentionally not enabled).

- `src/warden/select.rs` contract (verified against source):
  `auto` → namespaced when the probe passes *and* the policy is
  satisfiable; native only when namespaced is unavailable **and**
  native satisfies the policy; **refuse** otherwise. Explicit
  `namespaced` never falls back; explicit `native` refuses on
  unsatisfiable policy. This matches the documented behavior — no doc
  correction needed.
- Ubuntu ships `kernel.apparmor_restrict_unprivileged_userns` since
  23.10 — **opt-in there; enabled by default from 24.04**
  (`/usr/lib/sysctl.d/10-apparmor.conf`). Under it, an unconfined
  process can still create a user namespace but receives one *without
  capabilities* (the `unprivileged_userns` default profile); the
  failure then surfaces at the first operation needing capabilities
  inside it — e.g. our probe's combined
  `unshare(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS)` reports stage
  `unshare` via `EPERM`. If the default profile is absent, AppArmor
  instead denies unconfined userns *creation* outright — a different
  failure shape at the same stage. Either way `auto` resolves
  native-or-refuse exactly as designed. Admin opt-out is a sysctl
  (host config, out of product scope).
- WSL reference host: neither that sysctl nor
  `kernel.unprivileged_userns_clone` exists; `user.max_user_namespaces
  =15636`; `unshare --user --map-root-user --net` → **OK** —
  namespaced route available here, restriction absent as documented.

### Verdict — **current behavior confirmed correct**

`auto` semantics and the Ubuntu restriction's documentation are
accurate; no change required beyond this record.

## Execution summary (record-format fields)

| item | content |
|---|---|
| target | improvement plan §3 R-02 / PR guide PR-11 (baseline `f00e28a`, v0.5.1) |
| environment | Windows 11 Pro 26200.9711 x86-64 non-elevated; WSL2 Ubuntu 24.04.2, kernel 6.18.54.1; mxc-sdk 1.0.1; landlock crate 0.4.7 |
| reproduction | Full sources kept in the durable bundle `.local/pr11-mxc/src/` — `mxc-probe/` (Cargo manifest + `src/main.rs`; run `cargo run -- support|run|spawn`, env toggles `MXC_PROBE_EXE`/`MXC_PROBE_COMMAND`/`MXC_PROBE_BIND`/`MXC_PROBE_ALLOW_ADDR`/`MXC_PROBE_ALLOW_CIDR`/`MXC_PROBE_DENY_ADDR`/`MXC_PROBE_NO_LB`/`MXC_PROBE_NO_FS`/`MXC_PROBE_NO_NET`/`MXC_PROBE_EXTRA_RO`/`MXC_PROBE_DEFAULT_ENV`), `winiso-copy/` (the `tests/fixtures/windows_isolation` tree with only `ffi.rs`'s `ole32`→`combase` link-name change, rebuilt `rustc --edition 2021 -O`), `ll.py` (`landlock_create_ruleset` version syscall 444). Required inputs: four scratch dirs with `ro-read.txt`/`deny-read.txt`/`ungranted.txt` (probe creates them), a host TCP listener (probe binds it), the winiso `attempts` battery as the child binary; `unshare --user --map-root-user --net` for the userns leg |
| counts | Windows: `support` + 5 container `run` variants + 1 `spawn` leg — ≈ 80 measured attempt ops total (14 ops/leg), all produced evidence (no skips); ole32 bisect 6 exes (2 pass, 4 consistent failures); interpreter legs: node fail / python pass; Linux: 1 ABI probe + 1 userns leg — pass; macOS: 0 runs — unverified |
| controls | see mapping table + per-target sections |
| audit | `CaptureDenials` advertised but unverified; ES notify ≠ enforcement; Landlock v7+ audit deltas are watch items |
| compatibility | node.exe blocked in MXC tier-1 (ole32 init) — Python ok; loopback all-or-nothing vs warden's per-dest model; destination-scoped UDP impossible at any Landlock ABI |
| resources | unmeasured: per-launch container cost (MXC), ES event volume |
| cleanup | scratch probe outside the repo; `.local/pr11-mxc/` evidence only; repo tree clean; no system settings changed |
| next decision | MXC: hold → conditions listed; ES: declined; Landlock v10/v11: hold → crate+kernel gates; Ubuntu/`auto`: confirmed correct |
