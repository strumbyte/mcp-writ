# macOS parity deep-dive (PR-11 follow-on)

Follow-up to `successor-mechanisms-2026-11.md`, which recorded macOS as
"0 runs — unverified": the ES-descendants evaluation was documentation-only
and the closing gap list said "nothing further to close" without having
probed a real macOS host. This document is the macOS-side deep-dive: every
mechanism that could narrow the OS gap against the Linux namespaced route
and Windows PSEC tier-1, probed or source-verified on the reference host.

Status: **probes executed on the reference host** — macOS 26.6.2
(build 25G83), arm64, xnu-12377.161.14, 2026-11-08. Evidence sources and
binaries kept in `.local/pr11-macos/` (`src/es_gate.c`, `src/desc_probe.c`,
`src/kq_bisect.c`, `src/kq_bisect2.c`, `src/desc_probe2.c`, `src/spawn_try.c`,
`src/udp_relay.py`, `src/udp_wk.py`, `ent.plist`).

## What the gap is

The macOS native path (`sandbox-exec` + Seatbelt) already enforces fs /
mach-IPC / inbound-listen / loopback-pinned TCP. The parity gaps versus
the Linux namespaced route:

1. **descendant-lifetime boundary** — `sandbox require_lifetime_boundary`
   (default `#true`) refuses macOS supervised launches outright:
   "no cgroup, no subreaper" (`src/warden/spawn.rs` x2 call sites). With
   `=#false` the only teardown is `killpg`, which `setsid` escapes
   (`macos_proxy_run.rs::kill_group` documents the pgid assumption).
2. **destination-scoped UDP egress** — proxy mode denies UDP outright;
   Linux namespaced has `dnsgate` (name-bound UDP answers mint grants).
3. **kernel-deny observability** — Linux emits audit records for
   seccomp-denied ops; the macOS path had no recorded observation channel.

## Measured results

### 1. Lifetime boundary — the core gap

| Candidate | Result | Evidence |
|---|---|---|
| `EVFILT_PROC` `NOTE_TRACK`/`NOTE_TRACKERR`/`NOTE_CHILD` | **kernel-disabled** — `kevent` attach → `ENOTSUP` on every target (spawned child, `fork()` child, self), every flag combination | `kq_bisect.c`/`kq_bisect2.c` runs; xnu `main` `bsd/kern/kern_event.c::filt_procattach` returns `ENOTSUP` unconditionally when any of the three flags is set (source-verified). The historical fork-tracking mechanism is dead, not just restricted. |
| `NOTE_FORK`/`NOTE_EXIT`/`NOTE_EXITSTATUS`/`NOTE_EXEC` on a known pid | **works** | `desc_probe2` — FORK and EXEC events delivered for fork+exec and `posix_spawn` children |
| NOTE_FORK → `proc_listallpids` + ppid-ancestry enumeration | **best-effort — measured race** | `desc_probe2 supervise all`: all spawn patterns discovered (fork-exec, posix_spawn, **setsid-escape caught**, `sh -c 'sleep &'` grandchildren, double-fork) and kill-swept to `still-alive=0` — **but** when the intermediate process exits before the sweep walks the orphan's ancestry, the link is lost: the orphan reparents to launchd (ppid=1 observed) and survives the kill sweep (observed in an early run; later runs won the race). Enumeration-based tracking cannot atomically capture an orphan — exactly what `NOTE_TRACK` used to do in-kernel. |
| `proc_pidinfo` ppid walk / `sysctl` | same enumeration class — the race is inherent, not implementation-specific | covered by the desc_probe2 mechanism |
| ES `es_new_descendants_client` (macOS 27+) | **kernel-scoped subtree visibility — cannot run here** | symbol absent on 26.6.2 (`dlsym` → NULL); macOS-27 SDK header + Apple docs: auth+notify for the whole descendant subtree, existing + future, recursive — but **event delivery is not a complete sweep roster**: messages can be dropped under load and concurrent forks, so the supervisor's method for obtaining a guaranteed-complete descendant set (reconciliation beyond the event stream) is an open design question — the lifetime-boundary claim stays **conditional until that roster method is established**, alongside the other caveats: header notes state "Descendants clients can already kill or suspend their child processes directly"; no auto-teardown when the client dies; caller/descendants cannot exec setuid/setgid unless euid 0; still **no IP-network auth event** (26/27 SDK `es_event_type_t`: UIPC_*/XPC_CONNECT/BOOTSTRAP_* auth events exist; nothing for TCP/UDP). Third-party dev evidence (ukai "reciprocal custody" experiment) shows guardian+ward descendants clients covering fork/exec/exit and killing on custody loss — the pattern is real, entitlement-gated. |
| **Seatbelt `(deny process-fork)`** | **kernel-enforced — the only lifetime boundary available to the native path today** | `spawn_try` under the profile: `fork()`/`posix_spawn()`/`vfork()` all → `EPERM`. A workload that needs no children gets subtree = {self} for free — cgroup/job-object equivalent for that policy class. |
| `(deny process-exec)` | **unusable for launching** | the workload's own first exec is denied → `sandbox-exec` fails `execvp` (exit 71). Cannot express "exec once then no more". |
| pf per-uid egress / OpenBSM `/dev/auditpipe` | **root-only** — out of scope for the unprivileged CLI | `pfctl -sr` → `/dev/pf: Permission denied`; `/dev/auditpipe` is `crw------- root:wheel` |
| Apple `container` (Virtualization.framework VM) | already validated (`apple-container.md`) — VM teardown is the strong boundary | `container` 1.5.0 installed on this host |

**Verdict for the boundary gap:** there is no unprivileged
kernel-enforced descendant teardown for a *multi-process* workload on
macOS ≤ 26 — confirmed negatively with measurements, not just absence of
docs. The honest ladder: (a) policies tolerating `deny process-fork`
gain a real kernel boundary today (currently unconditionally allowed in
the generated profile — an opt-in policy knob would close this class);
(b) macOS 27's ES descendants client gives race-free subtree membership +
kill authority, gated on the Apple-granted entitlement plus a supervisor
that sweeps on client death; (c) strong-boundary workloads keep the
`container` VM route.

### 2. Destination-scoped UDP — loopback datagram relay is viable

Profile `(deny network-outbound)(allow network-outbound (remote udp "localhost:PORT"))`:

- `sendto` to the relay port **succeeds, and the relay's reply comes back**
  without any explicit inbound grant (socket-scoped reply path).
- `sendto 192.0.2.1:53` → `EPERM`; `sendto` to a *different* loopback
  port → `EPERM` (the port pin is real, not `localhost:*` slippage).

So the same architecture as `connect-proxy` (SBPL pins egress to a
loopback endpoint; the launcher-side endpoint applies per-destination
policy) can carry UDP — e.g. a datagram relay that forwards allowlisted
destinations and answers policy-declared names itself (the dnsgate
analog). **Important honesty caveat:** SBPL does not redirect
`sendto(remote, port)` to the relay — it merely *permits* the loopback
endpoint and denies everything else. The workload must actively direct
its datagrams at the relay and convey the original destination (e.g.
a SOCKS-UDP-style header, an env-injected relay address, or a custom
resolver pointed at the relay for DNS) — general destination-scoped UDP
**and** in-sandbox DNS therefore stay **conditional on that workload
integration being implemented**, not on kernel support, which is
complete (the pin + duplex reply path measured above).

### 3. Kernel-deny observability — the unified-log channel exists

`log stream`/`log show` **unprivileged** captures per-denial records:

```
Sandbox: cat(42407)    deny(1) file-read-data /private/etc/ssh/ssh_config
Sandbox: Python(42620) deny(1) network-outbound remote:*:80
Sandbox: Python(42620) deny(1) network-outbound remote:*:53
Sandbox: diagnosticd(41863) deny(1) network-inbound /private/var/run/.sim_diagnosticd_socket
Sandbox: imagent(787)  deny(1) mach-lookup com.apple.contactsd.persistence
```

fs, outbound-TCP, outbound-UDP, inbound-listen and mach-lookup denies all
emit `Sandbox: <proc>(<pid>) deny(1) <op> <target>` lines. This is the
macOS observation channel for kernel-enforced denies (parity with the
seccomp-audit records on Linux) — usable to surface
`sandbox.*_denied`-style visibility for the native path without changing
enforcement. Note: deduplicated as "N duplicate reports" for repeats.

### 4. ES entitlement/distribution gate — measured

- `es_new_client` on this host, unprivileged unentitled binary →
  `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` (5) — classic ES requires
  root first.
- The same binary ad-hoc codesigned with a self-declared
  `com.apple.developer.endpoint-security.client` entitlement → **killed
  at exec (`Killed: 9`)** — the entitlement cannot be self-minted;
  Apple-issued provisioning is required for `com.apple.developer.*`.
  The distribution risk noted in the successor-mechanisms record is
  confirmed as a hard local gate, not just a policy statement.
- `es_new_descendants_client` symbol does not exist on macOS 26.6.2 —
  `API_AVAILABLE(macos(27.0))` is real; any ES-based parity mechanism
  carries a hard OS floor.

### 5. Resource limits — partial parity levers exist

`proc_rlimit_control` (sys/resource.h) exposes `RLIMIT_CPU_USAGE_MONITOR`
+ `CPUMON_MAKE_FATAL`, `RLIMIT_WAKEUPS_MONITOR` + `WAKEMON_MAKE_FATAL`,
and `RLIMIT_FOOTPRINT_INTERVAL` — per-process fatal-on-exceed CPU /
wake-rate caps and footprint tracking (Darwin `RLIMIT_AS` is historically
unreliable). No cgroup-parity, but CPU-fatal limiting is expressible
against a spawned workload today.

### 6. sandbox-exec standing on this host

Present (`/usr/bin/sandbox-exec`, Aug 2026 build), fully functional on
26.6.2 — no deprecation banner emitted. External status unchanged:
deprecated ~9 years, no removal signal, apple/containerization#737
(asking for a removal timeline / non-App-Store replacement) is open and
unanswered by Apple. The kernels-side Seatbelt enforcement is what every
AI-agent sandbox on macOS uses; `deny process-fork` etc. work as
measured above.

## Round 2 (same host, 2026-11-08) — remaining candidate space

A second pass over every mechanism class not yet probed, aimed at the
still-open lifetime-boundary gap and the sandbox-exec dependency itself.
Sources in `.local/pr11-macos/src/` (`escapes.c`, `job.plist`,
`sb_init.c`, `stub.c`, `nested.c`, `hello.c`+`Info.plist`,
`inspect*.c`, `sbcheck*.c`, `cpumon*.c`, `kq_*.c`).

### Lifetime boundary — the remaining candidates all fail or gate

| Candidate | Result | Evidence |
|---|---|---|
| Process **coalitions** (`posix_spawnattr_setcoalition_np`, `coalition_info_pid_list`) — kernel-maintained membership immune to reparenting | **gated, unusable** | xnu `bsd/kern/kern_exec.c`: spawning into a coalition other than one's own requires membership in a *privileged* coalition or `COALITION_SPAWN_ENTITLEMENT` (private); `unrestrict_coalition_syscalls` tunable defaults off (`coalition.c`). Spawn-into-own-coalition would merely join the caller's coalition — too coarse (contains unrelated processes). |
| **launchd user-domain job** — `launchctl bootstrap`/`bootout` with launchd as PID-1 reaper | **pgid-scoped only — measured negative** | Job ran `escapes s n s` (one same-pgid child + two setsid'd children). `bootout` killed the job pid and the same-pgid child; both new-session descendants survived reparented to launchd (ppid=1). launchd teardown does not attribute reparented/new-pgid descendants to the job — same class of coverage as pgid-kill. |
| ES descendants client | unchanged — hold (round-1 verdict) | would be the only race-free subtree membership, but entitlement + macOS 27 + no auto-teardown |

**Conclusion hardens:** there is no unprivileged kernel-enforced
descendant teardown on macOS ≤ 26 — now measured negative across
kqueue, enumeration, launchd, and coalition paths, not just absent from
docs. The ladder stands: `deny process-fork` (subtree={self}) →
ES-descendants (27+, entitlement) → `container` VM.

### sandbox-exec dependency itself — exits

| Candidate | Result | Evidence |
|---|---|---|
| `sandbox_init` (libsandbox, deprecated since 10.8) | **works — programmatic SBPL application** | `sb_init`/`stub`: custom SBPL applied in-process; stub → `sandbox_init` → `execvp(workload)` — profile survives exec, fs deny + `deny network*` enforced (cat → EPERM, connect → EPERM). Removes the `/usr/bin/sandbox-exec` binary dependency (an mcp-writ-owned stub does init+exec). Same deprecation class as the CLI, but the kernel side is shared. `sandbox_init_with_parameters` additionally exported (undeclared — Chromium-style `dlsym` entry, adds `-D` param substitution). |
| **Nested `sandbox_init`** | **denied once sandboxed — measured** | first init → 0; second init inside the sandbox → `EPERM` under both an `allow default` outer and a `sandbox-exec` outer. A sandboxed workload can neither escape nor tighten; sandbox can only be applied pre-exec by an unsandboxed stub. (The codex issue's "nested sandbox-exec failure mode" is this same wall.) |
| **App Sandbox** (`com.apple.security.app-sandbox`) | **activatable but coarse** | ad-hoc codesign with the entitlement + embedded `__TEXT,__info_plist` (CFBundleIdentifier) → secinit applies the real app sandbox: ssh_config read EPERM, `/tmp` write EPERM. Without the plist the same binary is SIGTRAP'd at secinit. Not Apple-gated (unlike ES), but expressiveness is entitlement-level: all-or-nothing file/net — cannot express per-path grants or per-destination egress → fails warden's contract granularity. |
| **`sandbox_check(pid, op, type, arg)`** (private, `libsandbox`) | **post-spawn enforcement verification — measured working unprivileged** | `sandbox_check(sandboxed_child, "file-read-data", 1, path)` → 1 = would-be-denied for the ssh path, 0 = allowed for /etc/hosts; `network-outbound` → 1 under deny, `network-inbound` → 0, `mach-lookup` → 1, `process-fork` → 0. **This refutes the product's "in-kernel profile acceptance is not observable"** — a launcher can assert per-op enforcement on the spawned pid at runtime. |
| `sandbox_inspect_pid` | present but returns 1/empty on our children — no useful introspection | `inspect*.c` |

### Extended SBPL op matrix (profile-load acceptance, `(deny OP)`)

Accepted: `ipc-sysv-sem`, `ipc-sysv-shm`, `ipc-posix-shm`,
`ipc-posix-sem`, `sysctl-read`, `sysctl-write`, `system-socket`,
`signal`, `mach-register`, `file-ioctl`, `user-preference-read`,
`process-info*`, `device-camera`, `dynamic-code-generation`
(W^X/JIT-deny analog), `signal (target others|children|same-sandbox)`.
Rejected (nonexistent): `process-codesigning-status`,
`signal (target all)` (`all` is not a qualifier).

**unix-domain sockets:** `deny network*` blocks both `connect` and
`bind` (EPERM each). There is **no per-path unix-socket selector** —
`remote unix`/`network-path` are rejected — and `deny file*` on the
socket path does not gate `connect` (returns ECONNREFUSED, not EPERM —
the deny is bypassed at the socket layer). macOS unix-socket
granularity is therefore all-or-nothing — a parity gap against
Landlock ABI v9 pathname scoping, same class as Linux < ABI v9.

### Resource controls — measured

`setrlimit(RLIMIT_CPU, {2,2})` → SIGXCPU kill verified.
`proc_rlimit_control(pid, RLIMIT_CPU_USAGE_MONITOR, CPUMON_MAKE_FATAL)`
→ accepted (xnu: sets `TASK_RUSECPU_FLAGS_FATAL_CPUMON`);
`RLIMIT_THREAD_CPULIMITS` is self-only percent+refill cap;
`RLIMIT_WAKEUPS_MONITOR` is a silent no-op in current xnu ("no longer
supported" in `kern_resource.c`). Still no aggregate-per-subtree
accounting (no cgroup class) — per-process limits only.

### `sandbox_check` permission scope

Callable unprivileged on same-uid spawned children — the launcher-side
use case. `signal` probing with a pid argument returns −1 (not a
membership oracle).

## Round 3 (same host, 2026-11-08) — spawn-attribute surface + residual primitives

Third pass over the `posix_spawnattr` inventory and remaining syscalls —
the axes the first two rounds left unexplored (resource caps at spawn,
spawn-time MAC extension, process-control primitives). Sources in
`.local/pr11-macos/src/` (`jetsam.c`, `cpumon_spawn.c`, `suspended.c`,
`misc_probe.c`, `fdlimit.c`, `last_probe.c`, `psd.c`).

| Candidate | Result | Evidence |
|---|---|---|
| `posix_spawnattr_setjetsam_ext` (spawn-time memory limits, `MEMLIMIT_*_FATAL`) | **accepted, non-enforcing on macOS** | setter + spawn succeed (memlimit_active=50MB, fatal flag); a 400 MiB allocator ran to completion — jetsam memlimits are advisory on desktop macOS (kernel code path `memorystatus_set_memlimits` exists; enforcement is the iOS jetsam regime) |
| `posix_spawnattr_setcpumonitor` (percent+interval at spawn → `TASK_POLICY_RESOURCE_ATTRIBUTE_NOTIFY_EXC`) | **accepted, non-killing** | 5%/1s monitor on a busy-loop: hog alive at 8s — the monitor raises EXC_RESOURCE exceptions, not a kill; enforcement would need a registered exception port + decision logic (observation-shaped, not a bound) |
| `POSIX_SPAWN_START_SUSPENDED` (0x0080) | **works — spawn lands in SSTOP, SIGCONT resumes** | child observed `state=SSTOP` at 1s then resumed on SIGCONT — the arm-before-run pattern exists (suspend, arm watchers, resume), though the suspend lands at task creation, so it narrows but does not eliminate the tracking race |
| `setrlimit(RLIMIT_CPU)` | **enforcing** (round 2: SIGXCPU kill at 2s) | — |
| `posix_spawnattr_set_filedesclimit_ext` / `set_threadlimit_ext` | **setter exists; semantics unverified** | int arg accepted but a spawned hog opened 61k fds under a "8" request — single-int usage does not map to the visible cap; needs format verification before use |
| `task_for_pid` / `ptrace(PT_ATTACHEXC)` on same-uid child | **both denied** | `task_for_pid` → `kr=5`, `ptrace` → `EPERM` — no per-task port, no debugger attach unprivileged on this host |
| `pid_suspend` / `pid_hibernate` | **privileged** | `pid_suspend(child)` → `EPERM` |
| `pid_shutdown_sockets(pid, 1)` | **accepted unprivileged** | per-pid socket-teardown primitive exists — marginal (per-pid, not a tree; network-kill only) |
| `posix_spawnattr_setmacpolicyinfo_np` ("Sandbox" extension at spawn) | **mechanism exists; payload-format-gated** | setter + spawn accept a "Sandbox" extension — the spawn-time MACF extension path is real (xnu `spawn_copyin_macpolicyinfo` → per-policy data consumed at exec), but the Sandbox blob format is private; `sandbox_init`-stub is the practical equivalent today |
| `proc_bsdinfo.pbi_flags` as is-sandboxed flag | **not discriminating** | identical flags for sandboxed vs plain child — `sandbox_check` stays the verification API |
| `POSIX_SPAWN_PCONTROL_*` | **swap-exhaustion response only** | `p_pcaction` is consumed solely by the memorystatus out-of-swap path (`proc_dopcontrol`) — not a lifecycle boundary |
| `posix_spawnattr_set_uid_np` / persona | requires privilege to change uid (setuid rules) | — |
| `POSIX_SPAWN_SETSID` (0x0400) | exists — gives the child a new session | works against containment (escape direction), not a primitive for us |
| `subsystem_root_path` | dyld/exec image-root plumbing (driverkit/subsystem roots), `p_subsystem_root_path` — not a fs boundary | source-verified in `kern_exec.c` |

**Bottom-line delta after three passes:** the macOS unprivileged
primitive inventory is now fully swept. Nothing new changes the verdict
ladder — `deny process-fork` (subtree={self}), ES descendants (27+,
entitlement, no auto-teardown), `container` VM remain the only
lifetime-boundary candidates; `sandbox_init`-stub + `sandbox_check` +
unified-log + UDP-relay remain the adoptable-now closes. The new negative
results (jetsam/cpumonitor non-enforcing, task_for_pid/ptrace/pid_suspend
denied, launchd/coalition/NOTE_TRACK dead) bound the search space
completely: **there is no unprivileged kernel-enforced descendant
teardown on macOS ≤ 26, and no spawn-attr resource cap that kills.**

## Round 4 (same host, 2026-11-08) — op-granularity, introspection, container net

Residual surfaces: SBPL qualifier granularity, runtime-identity
introspection, sandbox extension syscalls, and the `container` network
model. Sources in `.local/pr11-macos/src/` (`csops_probe.c`).

| Probe | Result |
|---|---|
| `(allow process-exec (literal "path"))` | **accepted** — exec allowlist granularity exists at the SBPL level (a profile can pin which binaries may exec) |
| `(interpreter ...)` qualifier | **does not exist** on macOS 26 (`unbound variable`) |
| `(with no-sandbox)` modifier on `allow process-exec` | **exists as an allow-side escape hatch** — children exec'd under that modifier run outside the sandbox. Deny-default profiles never grant it; noted so a future profile audit keeps it that way |
| `(deny network-inbound (local tcp "localhost:*"))`, `(deny network-bind)` | **accepted** — inbound listen can be scoped (port/source-class at op level), matching the outbound granularity |
| `appleevent-send` | **accepted** — Apple Events IPC is gateable (`appleevent-recv`, `xpc-service-lookup`, `distributed-notification` are not ops) |
| `mach-per-user-lookup`, `mach-task-name`, `ipc-posix-shm-write-data`, `file-read-xattr`, `file-write-xattr`, `file-mount` | **all accepted** — the op space covers shm-write-data and xattr granularities too |
| `system()`/`popen`/`subprocess` under `(deny process-fork)` | **all EPERM** — the fork gate covers every libc spawn path (completing the fork/posix_spawn/vfork battery) |
| `csops(pid, CS_OPS_STATUS, &flags)` | **works unprivileged on same-uid pids** — returns code-sign flags (valid/hard/kill/enforcement/requireLV) of a spawned child: a runtime identity/integrity introspection channel |
| DevToolsSecurity | **disabled on this host** — consistent with `ptrace` EPERM; debugger-based observability is opt-in system config, not a product path |
| `__sandbox_ms`/`__sandbox_me`/`__sandbox_mm`/`__sandbox_msp` | private sandbox syscalls exist in libsystem_kernel (the `mac_syscall` plumbing `sandbox_init` rides on, plus the extension-issue/consume machinery); `sandbox_issue_extension` is **not** in libsandbox's public exports — runtime-grant extensions stay private territory |
| `container run --network` | vmnet-named-network attach + `--dns*`/`--no-dns` only — **no per-destination egress control at the container substrate**; destination scoping in the VM route stays inside-guest (the Linux warden/Landlock layer), consistent with `apple-container.md` |

## Round 5 (same host, 2026-11-08) — containment completeness probes

| Probe | Result |
|---|---|
| `system()`/`popen`/`subprocess` under `(deny process-fork)` | all EPERM — the fork gate covers every libc spawn path |
| `(deny signal)` blanket → sandboxed child `kill(victim, SIGTERM)` | **EPERM, victim survives** — outbound signal containment works under deny-posture |
| `(deny signal (target others))` → same test | **did NOT block** — `target others` does not mean "processes other than self"; the qualifier taxonomy is `self/others/children/same-sandbox` and `others` did not match a same-uid outside process. The product's `(allow signal (target self))` under deny-default is the correct scoping — verified: `signal (target self)` allow + deny-default → SIGTERM to other proc still EPERM |
| `(deny process-info*)` | **breaks process spawning entirely** (subprocess → EPERM) — process-info* denial is too aggressive to use as an enumeration shield for a spawning workload |
| `socketpair(AF_UNIX)` under `deny network*` | **works** — local AF_UNIX IPC is not killed by the network deny (correct semantics: socketpair is IPC, not egress) |
| `(remote udp "localhost:PORT")` covers `::1` | **verified** — the same pin permits v6 loopback relay (duplex) — the UDP-relay design inherits v4+v6 |
| `pbi_puuid` (proc_bsdinfo unique uuid) | exists for pid-identity/pid-reuse-proof sweeps |
| `container network` | named-network management exists (`create`/`ls`/`inspect`); service not running on this host; no per-destination rule surface |

## Round 6 (same host, 2026-11-08) — residual primitives + product-profile check

| Probe | Result |
|---|---|
| `memorystatus_control(cmd, child_pid, ...)` (parent-set jetsam/memlimit on another process) | **all 20 commands → EPERM** — resource-limit application to another process is privileged |
| `proc_pidinfo(child, PROC_PIDLISTFDS)` | **works unprivileged** — the supervisor can enumerate a spawned child's open fds (observability axis) |
| `file-issue-extension` / `mach-issue-extension` ops | **accepted** — extension-issuance is gateable; `file-issue-extension-target` does not exist |
| setuid exec inside sandbox (`sudo`) | **execvp → EPERM** — sandboxed processes cannot exec setuid binaries (consistent with the ES descendants restriction) |
| `log show --style json` deny records | records carry `eventMessage`/`formatString` — parseable but formatted strings (no structured op/path fields) |
| **`sandbox_check` against the real product profile** | **verified end-to-end**: spawned `mcp-writ run --policy p.kdl --audit-log … -- /bin/sleep 60` (real SBPL from `macos_sandbox.rs`), then `sandbox_check(69466, …)` returned DENIED for `file-read-data /private/etc/ssh/ssh_config`, `network-outbound`, `network-inbound`, `mach-lookup com.apple.mDNSResponder`, `file-write-data` on `~/.ssh` and `/tmp`, `signal`; **allowed** for `file-read-data /etc/hosts` and `process-fork` — matching the generated profile (`deny host="*"`, deny-default fs writes outside grants, `process-fork` allowed, `signal (target self)`). The "profile acceptance not observable" gap is closed at the product level, not just toy profiles |

## Round 7 (same host, 2026-11-08) — task ports, QoS/resource policy, last ops

| Probe | Result |
|---|---|
| `task_name_for_pid(child)` | **kr=0 — task NAME port obtainable unprivileged** on a same-uid spawned child. The name port gives limited introspection (`pid_for_task`, basic task info) but not `task_terminate`/suspend — observability, not a kill primitive |
| `taskpolicy -b -p <child>` | **applies silently (rc=0)** — `process_policy`/`task_policy` resource policy (background/utility QoS throttle) can be set on a spawned child unprivileged: a *deprioritization* lever, not a cap |
| `task_inspect_for_pid` | not declared in public headers (inspect port is entitlement-gated) |
| `file-clone`, `iokit-open`, `iokit-get-properties`, `mach-bootstrap` ops | **accepted** — clonefile/IOKit/bootstrap-domain gates exist |
| `debug-deny`, `darwin-user-dir` | not ops |

After seven passes the sweep is complete at three layers: kernel
primitives, libc/syscall surface, and spawn-attr surface — plus
product-level verification. The parity story is fully bounded.

## Round 8 (same host, 2026-11-08) — socket-family coverage + rlimits + modifiers

| Probe | Result |
|---|---|
| `socket()` family sweep under `(allow default)(deny network*)` | **`deny network*` is INET/UNIX-only, not a full egress block** — `PF_SYSTEM`(kern_control), `PF_ROUTE`(routing socket), AF_UNIX all still CREATED; PF_NDRV/PF_KEY/AF_LINK/ICMP-raw fail for other reasons. A workload under allow-default + deny-network* retains kernel-control and route-observability channels |
| same sweep under product-like `(deny default)` posture | **all denied properly** — `PF_SYSTEM` gated by `system-socket`, others by deny-default → the product's deny-default base already covers every family; the gap only exists for allow-default profiles |
| `ulimit -u`/`RLIMIT_NPROC` | **enforced on modern macOS** — `ulimit -u 20` → `fork: Resource temporarily unavailable` (per-uid, not per-subtree — a fork-bomb brake, not a boundary) |
| `(with report)` / `(with notify)` SBPL modifiers | rejected on deny (`report modifier does not apply to deny action`) / nonexistent — deny lines already log by default, no extra channel needed |

## Round 9 (same host, 2026-11-08) — coexistence + same-sandbox scoping

| Probe | Result |
|---|---|
| TCP-proxy pin + UDP-relay pin coexistence `(remote tcp "localhost:P1")` + `(remote udp "localhost:P2")` under `deny network-outbound` | **both permitted, everything else EPERM** — the connect-proxy architecture composes cleanly with a UDP datagram relay; the combined egress design is viable |
| `signal (target same-sandbox)` allow → `kill(host_pid, SIGTERM)` | **EPERM** — same-sandbox scoping restricts signaling to the sandbox domain; host processes stay protected |
| `(deny signal)` vs `(deny signal (target others))` | confirmed earlier: blanket/`self`-scoped allow are the working forms; `target others` does not scope outside processes |

## Verdicts

| mechanism | verdict |
|---|---|
| `(deny process-fork)` policy opt-in | **adoptable now** — kernel-enforced subtree={self} for child-free policies; new policy knob + profile line |
| loopback UDP datagram relay | **adoptable now (PoC)** — extends the connect-proxy architecture to UDP + DNS; closes the last native egress gap |
| unified-log `Sandbox:` deny observation | **adoptable now** — observation channel only; makes macOS kernel denies auditable (fs + net + mach + inbound measured) |
| `sandbox_init` in-stub application | **adoptable now** — removes the `/usr/bin/sandbox-exec` binary dependency; sandbox applied pre-exec by an mcp-writ-owned stub; same deprecation class as the CLI |
| `sandbox_check` post-spawn verification | **adoptable now** — private API via `dlsym`; verifies per-op kernel enforcement on the spawned pid (file/net/mach measured). Upgrades profile acceptance from "unobservable" to verifiable — note the API is private, so treat as advisory: compare each returned verdict against the policy's *expected* verdict for that op and refuse only on a mismatch (an expected deny is a pass); warn, don't refuse, if the symbol/API is absent |
| ES `es_new_descendants_client` (macOS 27+) | **conditional hold** — race-free subtree tracking + kill authority would satisfy `require_lifetime_boundary`, but: hard entitlement (exec-time kill measured), OS floor 27, still no IP-network auth (declined as an *enforcement* mechanism stands — this is a *lifecycle* re-evaluation), no auto-teardown on client death. Revisit when: entitlement is obtainable for distribution, or the product accepts an entitlement-gated opt-in backend on 27+ |
| `NOTE_TRACK` | **dead** — kernel-disabled in current xnu (measured + source-verified); do not design around it |
| NOTE_FORK + ancestry enumeration + pgid/pid sweep | **best-effort keep** — measured orphan race; valid as the `require_lifetime_boundary=#false` sweep, never as the boundary claim |
| launchd user-domain job teardown | **rejected** — pgid-scoped only; setsid'd descendants survive bootout (measured) |
| process coalitions | **rejected** — spawn-into-other-coalition needs private entitlement / privileged coalition; spawn-into-own is too coarse |
| nested `sandbox_init` | **impossible inside a sandbox** — measured EPERM; sandbox must be applied pre-exec |
| App Sandbox entitlement route | **rejected** — self-signable and activatable, but entitlement-coarse (no per-path/per-destination) |
| per-path unix-socket egress | **inexpressible in SBPL** — `network*` is all-or-nothing for AF_UNIX; `deny file*` does not gate connect |
| pf per-uid / auditpipe | **out of scope** — root-required |
| `proc_rlimit_control` CPU fatal + `setrlimit` | **usable now** — SIGXCPU kill measured; per-process only, no subtree aggregate |
| `csops` code-sign introspection | **usable now** — unprivileged runtime identity/integrity flags on spawned children; complementary to `sandbox_check` |
| `(with no-sandbox)` allow-side exec modifier | **watch** — an escape-hatch qualifier that exists; profile audits must keep it ungranted |
| spawn-attr resource caps (jetsam/cpumonitor/fd-limit) | **non-enforcing or unverified** — jetsam advisory, cpumonitor exception-only, fd-limit semantics unclear; `setrlimit` remains the enforcing path |

## Execution summary (record-format fields)

| item | content |
|---|---|
| target | improvement plan §3 R-02 / PR guide PR-11 — macOS-side parity continuation of `successor-mechanisms-2026-11.md` |
| environment | macOS 26.6.2 (25G83) arm64, xnu-12377.161.14; Command Line Tools SDKs 26.5/27.0; `sandbox-exec` present; `container` 1.5.0; clang; rustc 1.99.0 |
| reproduction | `.local/pr11-macos/` — `es_gate` (dlsym + `es_new_client`, plain and ad-hoc-entitled), `kq_bisect`/`kq_bisect2` (EVFILT_PROC flag matrix), `desc_probe`/`desc_probe2` (NOTE_TRACK attempt; NOTE_FORK + `proc_listallpids`/ppid ancestry sweep + kill), `spawn_try` (fork/posix_spawn/vfork under `(deny process-fork)`), `udp_relay.py`+`udp_wk.py` under a `(remote udp "localhost:PORT")` profile, `log stream`/`log show` captures under deliberate fs/net/mach denies; round 2: `escapes`+`job.plist` (launchd bootstrap/bootout teardown), `sb_init`/`stub`/`nested` (programmatic + nested sandbox_init), `hello`+`Info.plist` (App Sandbox activation), `sbcheck*`/`inspect*` (`sandbox_check`/`sandbox_inspect_pid` via dlsym), `cpumon*` (proc_rlimit_control + RLIMIT_CPU), `spawn_internal.h`/`kern_exec.c`/`coalition.c`/`kern_resource.c`/`kern_proc.c` (xnu source cross-checks); round 3: `jetsam`/`cpumon_spawn`/`suspended` (spawn-attr resource/suspend battery), `misc_probe` (task_for_pid/ptrace/bsdinfo-flags/filedesclimit), `fdlimit` (fd-cap check), `last_probe` (pid_suspend/pid_shutdown_sockets/setmacpolicyinfo), `psd` (socket-teardown leg) |
| results | NOTE_TRACK ENOTSUP ×7 configurations; enumeration sweep caught setsid/sh/double-fork patterns with one measured orphan-leak race; `deny process-fork` EPERM ×3 spawn syscalls; `deny process-exec` blocks launch exec itself; UDP relay duplex + two EPERM legs; deny lines for fs/network-outbound/network-inbound/mach-lookup observed; es_new_client→`ERR_NOT_PRIVILEGED`; ad-hoc ES entitlement → exec kill; round 2: launchd bootout leaks 2/2 setsid'd descendants; `sandbox_init` works in-stub and sandbox survives exec; nested init EPERM ×2 environments; App Sandbox applies for ad-hoc+plist-signed binary (ssh_config + /tmp write EPERM); `sandbox_check` verdicts verified for file-read-data/network-outbound/network-inbound/mach-lookup/process-fork (deny=1/allow=0); unix connect+bind EPERM under `deny network*`; RLIMIT_CPU SIGXCPU kill; coalition spawn gating + `unrestrict_coalition_syscalls` source-verified; round 3: jetsam memlimit advisory (400MiB survived a 50MB fatal request), cpumonitor exception-only (hog alive at 8s under 5%/1s), START_SUSPENDED → SSTOP + SIGCONT resume, task_for_pid `kr=5` + ptrace `EPERM` + pid_suspend `EPERM`, pid_shutdown_sockets accepted unprivileged, macpolicyinfo spawn extension accepted (format-gated), bsdinfo flags non-discriminating |
| controls | see tables above — mapped to lifetime-boundary, UDP egress, deny-observability, entitlement-gate, sandbox-dependency, resource-limit axes |
| audit | unified log is the macOS kernel-deny channel (unprivileged); `sandbox_check` gives launcher-side per-op enforcement verification; ES descendants client would add subtree auth events on 27+ only |
| compatibility | no product code touched; `deny process-fork` opt-in, the UDP relay, `sandbox_init`-stub application and `sandbox_check` verification are additive surfaces; `sandbox_check` is private API — advisory use only |
| resources | enumeration sweep is O(#pids × ancestry) per FORK event — negligible at workload scale; `log stream` tailing is cheap but external to the launcher; `sandbox_check` is a per-op syscall — usable post-spawn/assertion time |
| cleanup | all probe-spawned sleeps killed and verified gone (incl. the leaked orphan and the launchd-job survivors, removed by `pkill`/`kill`); test job booted out; no system settings changed; scratch confined to `.local/pr11-macos/` |
| next decision | five adoptable-now candidates (fork-deny opt-in, UDP relay PoC, deny-audit channel, `sandbox_init`-stub application, `sandbox_check` post-spawn verification) → candidate follow-up PRs; ES descendants client stays **hold** with concrete unblock conditions (entitlement + macOS 27 host + supervisor-side death-sweep design); launchd/coalition/notes recorded as measured rejections; `require_lifetime_boundary` stays refusing on macOS native for multi-process workloads — a `deny process-fork`-shaped policy class could satisfy it for subtree={self} cases without new kernel support |
