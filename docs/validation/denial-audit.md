# Denial-audit validation (improvement plan PR-08)

End-to-end verification that every *denied* operation is visible in the
JSONL audit stream — and that the paths where a denial cannot be
observed are pinned as a specification, never read as "nothing was
denied". This is the v0.3 integration closure for PR-03/04/06/07.

Status: **verified on the reference host** — recorded 2026-10-09 ·
PR-08 working tree (`f14bb3d` + working tree) · WSL2 on Windows 11,
kernel `6.18.40.1-microsoft-standard-WSL2`, x86-64, `rustc`/`cargo`
1.99.0. Windows legs (`enforcement.psec` on the product path) are owned
by the `windows-isolation` validation job — see the Windows row below.

Command:

```sh
cargo test --locked --test denial_audit_e2e -- --nocapture
# SIGKILL tail-loss measurement lives in its own target:
cargo test --locked --test audit_durability_e2e -- --nocapture
```

Recorded run: `denial_audit_e2e` 5/5 executed, 0 skipped, 0 ignored;
`audit_durability_e2e` 4/4 executed; `unotify_e2e` 13/13 executed,
0 skipped — the first run where the suite's legs actually ran (see
"Latent defects found" below).

## Latent defects found and fixed while landing PR-08

Bringing the Scenario B leg up for the first *real* execution exposed
three defects in the `unotify-run` path that had been masked because
the capability probe always reported "unsupported" — every
`unotify_e2e` leg had been silently skipping since introduction (the
PR-07 row in [test-matrix.md](../test-matrix.md) records "13/13
executed, 0 skipped", which under the broken probe means *not
executed*):

| Defect | Effect | Fix |
|---|---|---|
| `check_support` passed the `seccomp_notif_sizes` pointer in the `flags` argument of `seccomp(SECCOMP_GET_NOTIF_SIZES, 0, args)` | kernel EINVAL → every unotify leg skipped, Scenario B untestable | `src/warden/unotify/probe.rs` — `(op, 0, &mut sizes)` |
| `SECCOMP_IOCTL_NOTIF_ID_VALID` was invoked with the notification id *by value*; the ioctl is `_IOW` — the kernel `copy_from_user`s a `u64*` | EFAULT → every notification dropped unanswered → workload wedged in `seccomp_do_user_notification` | `src/warden/unotify/notif.rs` — pass `&id` |
| listener-fd `POLLHUP` raced a normally-exited child → "supervisor lost" misreported the child's own exit status | flaky statuses (e.g. 139 vs 143) | `src/commands/unotify_run.rs` — on supervisor loss, briefly wait for the child and report its status if it already exited |

One **unfixed** product defect was also confirmed and is recorded here
rather than silently changed (outside PR-08 scope): `allow host="443"`-style
bare-port entries — documented as Landlock TCP-port rules — are folded
by `normalize_policy_host` into WHATWG numeric IPv4 spellings
(`"443"` → `0.0.1.187`), so `net_intents`'s `parse_port_from_entry`
never sees a bare port and **no `NetPort` rule is ever emitted**. On a
kernel enforcing Landlock ABI V4 that makes every TCP `connect` fail
with EACCES after any supervisor CONTINUE — and it equally means a
PSEC projection would treat the entry as an address, not a port.

## Scenario A — denied RPC requests are audited

`scenario_a_denied_rpc_requests_are_audited` drives `run` over the
`scripted_stdio` fixture (OS sandbox bypassed — the RPC layer is what
this leg measures; `MCP_WRIT_SKIP_SANDBOX` runs never count as
OS-enforcement evidence). Per session:

| Client request | Wire result | Audit record asserted |
|---|---|---|
| `tools/call read_file` (policy-listed) | `result` | `tool_call.allowed`, `target_tool=read_file` |
| `tools/call exec_shell` (not in policy) | `-32001` error, `id=11` | `tool_call.denied` — `target_tool=exec_shell`, `request_id=11`, `severity=high`, `outcome=failure`, `action=denied`, "not found in policy" |
| `resources/read file:///etc/passwd` (no `mcp` rule) | `-32001` error, `id=12`, `no-rule` | `mcp_message.denied` — `target_tool=resources/read`, `request_id=12`, `action=denied`, `reason=no-rule`, `forwarded=false` |

The lifecycle bracket (`guard.started` … `guard.stopped`) around the
denials is asserted too — a burst of refused traffic must not break the
session accounting.

## Scenario B — direct :443 egress refused at the IP layer

`scenario_b_direct_443_egress_denied_and_audited` (Linux-only) runs the
real `mcp-writ unotify-run` over the `connect_probe` fixture with a
policy denying `192.0.2.0/24` + `host="*"`. Observed on the reference
kernel: workload exit 10 (`connect errno=13`/EACCES — the supervisor
denied it before the kernel ran the connect), and the audit log carries
`sandbox.network_denied` with `layer=ip`, `dest=192.0.2.1`, `port=443`,
`proto`, `decision=deny-cidr`, `action=denied`. The literal is
TEST-NET-1 documentation space — the attempt is never a real escape
even where the supervisor is not enforcing. Hosts without seccomp user
notification (`unotify::check_support` fails) record a skip — which
`MCP_WRIT_REQUIRE_E2E_TESTS=1` turns into a failure.

## Name layer — `dns-gate` refusals are audited

`dns_gate_denied_names_are_refused_and_audited` spawns the real
`mcp-writ dns-gate` binary (policy load → UDP listen → mock upstream →
audit file — the command's own path, not the in-process server the
`dns_gate_e2e` suite drives) twice:

| Leg | `--refuse-rcode` | Denied answer | Records asserted |
|---|---|---|---|
| default | — | REFUSED (5) | `sandbox.network_denied` `layer=name` for `blocked.example` (`decision=deny-host`, `rule=` matched rule, `rcode=refused`) and `denied.example` (`decision=not-allowed`), each `severity=high`/`outcome=failure`/`action=denied` |
| nxdomain | `nxdomain` | NXDOMAIN (3) | same shape with `rcode=nxdomain` |

Each leg also sends `allowed.example` through the mock upstream and
asserts `sandbox.network_resolved` — proof a refusal is policy, not a
dead gate. The gate runs under `--audit-sync` so every emitted record is
durable before the test kills the child; denied records are additionally
`log_committed` — durable before the refusal answer itself left.

## SIGKILL tail-loss measurement (PR-04 evidence)

`tests/audit_durability_e2e.rs` re-execs the test binary as an
audit-emitter child and SIGKILLs it mid-stream. Measured on the
reference host (kernel 6.18.40.1, debug build, 54-record run):

| Leg | Emitted | Survived | Lost |
|---|---|---|---|
| `sigkill_loses_buffered_tail_but_keeps_high_records` | 53 (3 high + 50 info) | 3 | `lost_info=50` — the whole buffered tail; all `high`+ records observed durable before the kill (writer_age_ms=0, high_drain_ms=10) |
| `audit_sync_loses_nothing_on_sigkill` | 54 | 54 | 0 — `--audit-sync` per-record flush+fsync |
| `drain_latency_of_each_sync_mode_is_measured` | 54 + 54 | buffered drain 11 ms, sync drain 157 ms | — |

These are **one machine's measurements, not guarantees**: the buffered
tail bound is "what the writer had not yet synced" (the ~1 s flush /
~5 s fsync ticks), and on a busier host the lost tail can be smaller or
larger. The *contract* the tests pin is narrower: a `high`+ record is
durable once the writer has dequeued it — the buffered leg waits for
the file to hold all of them before killing, so survival is pinned to
the immediate-sync path itself rather than to writer throughput — and
committed records survive; `--audit-sync` loses nothing the writer
reached; any channel shed or writer fault is accounted on
`guard.stopped` (`dropped=`/`writer_failed=`). A record still queued at
kill time is inside the volatile window regardless of severity —
`log_committed`/`--audit-sync` is the guarantee for emit-and-die
ordering. Numbers re-recorded per run in the test log (`MEASURE`
lines).

## Kernel-internal denials — unobservable by specification

Two Linux-only legs pin the reserved-event contract: the workload
provably hits a kernel denial while the audit stream correctly records
**no** `sandbox.*_denied` event.

| Leg | Fixture op | Denied by | Workload witness | Audit asserted |
|---|---|---|---|---|
| `landlock_fs_denial_is_unobservable_by_spec` | `kernel_deny_probe open <secret>` (secret outside every fs grant) | Landlock fs ruleset | stderr `KDP open=errno=13`, exit 10 | `server.connected` carries `enforcement.backend=landlock+seccomp`; lifecycle bracket present; zero `sandbox.*_denied` lines |
| `seccomp_connect_denial_is_unobservable_by_spec` | `kernel_deny_probe connect 192.0.2.1:443` (`socket`/`connect` absent from the syscall baseline) | policy seccomp `ERRNO` | stderr `KDP connect=errno=1`, exit 10 | same |

Both legs assert the spec rather than the absence: exit 10 proves the
denial *happened*, `backend=landlock+seccomp` proves *our* sandbox was
the denier, and `sandbox.file_denied`/`sandbox.process_denied` staying
absent is the documented contract — not a negative claim about
enforcement. A run where the probe never executes (no `KDP` marker) or
the operation is not denied reports *unavailable* (skip / failure under
`MCP_WRIT_REQUIRE_E2E_TESTS=1`), never a pass-by-absence. On kernels
below Landlock ABI V4 (< 6.7) the policy gains `sandbox
allow_degraded=#true` — the V1 fs/syscall denials still apply.

## Windows PSEC launch — `enforcement.psec` in JSONL

`winiso_live_product_run` (`tests/windows_isolation_e2e.rs`) launches
`mcp-writ run --windows-mechanism <m>` against a compiled probe on the
verified Windows host and now additionally parses the audit JSONL's
`server.connected` records:

- enforced PSEC launch → `enforcement.backend="psec"`,
  `enforcement.psec.schema_version="1.0"`, `egress_default_deny` /
  `egress_allow_rules` / `egress_rules_refused` present, `dry_run=false`,
  ≥1 `controls_applied`;
- enforced AppContainer launch → `enforcement.backend="appcontainer"`,
  `psec` member null — PSEC state must never appear on a non-PSEC
  launch;
- refused PSEC launch (launch-path refusal) → no `server.connected`
  claiming `appcontainer` — the silent fallback is caught in the audit
  stream, not only the report;
- policy-load refusal (`environment` allow-list the PSEC spec cannot
  express) → report records `failed`, audit file empty/absent — a
  pre-launch refusal leaves no `enforcement` record because the logger
  never started.

**Windows execution status:** `not run` on this host — the WSL2
verification above is Linux-only; `cargo check --target
x86_64-pc-windows-msvc --test windows_isolation_e2e` compiles the new
assertions. The `windows-isolation` job
(`scripts/validate-windows-isolation.ps1`,
`MCP_WRIT_REQUIRE_WINISO_TESTS=1`) owns execution and must re-record on
the merge commit — see [windows-isolation.md](windows-isolation.md).

## Registered ownership

- `denial_audit_e2e` — CI, Platform tests, Linux tests (all set
  `MCP_WRIT_REQUIRE_E2E_TESTS=1`); row in
  [test-matrix.md](../test-matrix.md).
- `audit_durability_e2e` — same workflows (pre-existing).
- `windows_isolation_e2e` PSEC legs — VM tests `windows-isolation` job /
  `scripts/validate-windows-isolation.ps1`.

## Known limits

- Scenario A bypasses the OS sandbox by design (`MCP_WRIT_SKIP_SANDBOX`)
  — it measures the RPC layer only; OS-enforcement evidence is the
  Landlock/unotify legs'.
- The `dns-gate` leg uses a mock upstream on loopback; no public resolver
  is contacted.
- `unotify-run` remains a PoC (connect-only, sockaddr TOCTOU, AF_INET/6
  only) — see [linux-unotify.md](linux-unotify.md).
- An audited `sandbox.network_allowed` is a **supervisor verdict**, not
  a guarantee the kernel ran the connect: `dynamic_grant_allows_connect`
  asserts the grant's `basis=allowlist-grant` record plus an answered
  notification (exit 0 or 10, never ENOSYS/hang). Whether the syscall
  then completes depends on Landlock `ConnectTcp` — with no expressible
  netport allow (see the normalization defect above), an ABI V4 kernel
  still denies it post-CONTINUE with EACCES, which the fixture surfaces
  as exit 10, indistinguishable by errno alone from a supervisor deny —
  the `network_allowed`/`network_denied` records are the discriminator.
- Buffered-mode loss numbers are host-timed; the invariant is the
  ordering contract, not a fixed count.
- Landlock-unobservable legs cannot run where the kernel lacks Landlock
  — they report unavailable rather than simulating the contract.
