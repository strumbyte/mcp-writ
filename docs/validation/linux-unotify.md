# Linux `unotify-run` PoC validation (improvement plan PR-07)

Real-kernel verification of the seccomp user-notification IP layer:
`mcp-writ unotify-run` spawns a workload under the ordinary Linux
sandbox pipeline (`no_new_privs` → Landlock → seccomp) plus a
`connect(2)` notification filter installed with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, and an in-process supervisor
evaluates each destination against the policy's IP-layer projection and
the DNS-gate dynamic allow list.

Status: **verified on the reference host** — recorded 2026-10-09 · PR-07
working tree · WSL2 on Windows 11, kernel
`6.18.40.1-microsoft-standard-WSL2`, x86-64, `rustc`/`cargo` 1.99.0.
This is a **PoC**: it is opt-in (`unotify-run` only) and the product
default `run`/`plan` paths are unchanged — `plan` still reports the
Linux IP layer as Auditor-only outside this command's own `--report`.

## Environment and capability gate

The command refuses to start — exit 2, explicit diagnostic — unless the
kernel provides:

- seccomp user notification (`SECCOMP_GET_NOTIF_SIZES` answers), and
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (Linux ≥ 5.5), proven by an actual
  fork → filter → notification → `CONTINUE` round-trip at startup, not
  just a version check.

WSL2 kernel 6.18 satisfies both. `sandbox.allow_degraded` cannot soften
this probe: without the mechanism there is no PoC to degrade to.

## What was exercised

`cargo test --test unotify_e2e` (10 tests, all executed — none skipped —
on the reference kernel) plus the `unotify` unit tests in `cargo test
--lib`. Coverage mapped to the PR-07 tasks:

| Spec item | Evidence |
|---|---|
| Notification filter + `NEW_LISTENER` + fd transfer | `dynamic_grant_allows_connect`, `unmatched_connect_denied_under_deny_all` — the fixture's `connect` only resolves through the listener socketpair handoff |
| `sockaddr` read from child memory | every connect leg — `process_vm_readv` on the notified pid decodes `AF_INET`/`AF_INET6` (mapped v4 normalized); unsupported families pass unmonitored, foreign-arch tasks are killed |
| Static CIDR allow/deny, deny precedence, `deny host="*"` posture | `denied_cidr_connect_is_refused_and_audited`, `unmatched_connect_denied_under_deny_all`, plus evaluator unit tests (deny-wins, literal-`host=` `/32`/`/128` projection, port-qualified allow refused at load) |
| Dynamic TTL-scoped grants | `dynamic_grant_allows_connect` (a `dns-gate --allowlist-export` snapshot grants the address) and `expired_grant_denies` (same address denied once `expires_at_unix_secs` passes — staleness is re-checked per connect, never trusted from the file) |
| Deny errno + continue flag | denied legs return `EACCES` to the workload; allowed legs return via `SECCOMP_USER_NOTIF_FLAG_CONTINUE` with no errno rewrite |
| `sandbox.network_denied` emission | `denied_cidr_connect_is_refused_and_audited` asserts the JSONL record — `layer=ip`, `dest`, `port`, `proto`, `pid`, `decision`, `rule`, `session_id` |
| Fail-closed audit | `fail_closed_policy_requires_audit_log` — a `fail_closed` policy without `--audit-log` refuses before spawn; mid-run sink failure turns *allow* verdicts into denials and kills the supervised child |
| Supervisor loss kills/blocks the child | `dropped_listener_makes_connects_enosys` — closing the listener fd makes pending/future `connect` return `ENOSYS` at the kernel; the command additionally SIGKILLs the supervised process group |
| Timeout/cancellation, teardown | `sigterm_terminates_supervised_child` — SIGTERM forwards to the process group, exit 143, no orphan |
| Capability/control-layer status in the report | `report_records_capability_and_layers` — `--report` JSON carries the `capability` block (mechanism, kernel, state), the two egress-layer dispositions, the rule table, and the fixed `limitations` list |
| CLI surface | `missing_command_is_a_parse_error` — `unotify-run` without `-- <command>` is a parse error, not a spawn |

Regression sweep on the same tree: `cargo test --lib` 1954/1954,
`plan_report_e2e` 24/24, `module_layering`, `docs_check`, fixture and
audit-durability suites green; `cargo clippy --all-targets` and
`cargo fmt --check` clean.

## Recorded limits (kept in `--report.limitations`)

- **`connect(2)` only.** Datagram egress via `sendto`/`sendmsg`
  (including TCP setup via `MSG_FASTOPEN`, which never calls
  `connect`), io_uring `IORING_OP_CONNECT`, and non-socket paths are
  out of scope for v0.3; nothing pretends otherwise. UDP `connect`
  *is* supervised (the destination is fixed at connect time).
- **TOCTOU on the sockaddr.** The supervisor reads the buffer with
  `process_vm_readv` between argument inspection and kernel use; a
  hostile workload can rewrite it in that window. This is inherent to
  user notification and is why this is a PoC, not a hardened boundary.
- **`AF_INET`/`AF_INET6` only.** Other address families are not decoded;
  their `connect` is answered `CONTINUE` unmonitored — recorded, not
  silently blessed, in the report.
- **Foreign-arch (compat) tasks are killed**, not supervised — the
  ABI-specific `sockaddr` layout is not decoded.
- **`proto` is best-effort.** Read via `pidfd_getfd` + `SO_TYPE` on the
  notified socket fd; failure records `unknown` rather than blocking.
- **`/proc`/memory-read permissions.** The supervisor reads only its
  own descendant over `process_vm_readv`, so `ptrace_scope` ≤ 1 admits
  it on the reference kernel; a child exiting between notification and
  read surfaces as an `EIO`/`ESRCH` read failure → `unreadable-dest`
  deny, never an allow. `ID_VALID` revalidation before `NOTIF_SEND`
  closes the pid-reuse race on the response path.
- **Filter ordering.** The notification filter is installed in
  `pre_exec` *before* the policy seccomp program (it needs
  `seccomp(2)`/`sendmsg(2)` to set up); kernel return-precedence keeps a
  policy `ERRNO` verdict ahead of `USER_NOTIF`, so a `connect` absent
  from `syscalls.allowed` is still denied at the syscall layer —
  unaudited there, as documented for all kernel-internal denials.
- **Kernel-internal denials stay unobservable** (improvement plan
  §1.6): only traffic the supervisor actually intercepts can emit
  `sandbox.network_denied`. The name layer (`dns-gate`) and this IP
  layer log disjoint paths; `run`/`plan` still do not rewire the
  workload's resolver through the gate.

## Reproduce

```bash
cargo test --locked --test unotify_e2e          # 10 tests; skips if kernel < requirement
cargo test --locked unotify                     # unit tests (evaluator, sockaddr, snapshot, BPF shape)
mcp-writ unotify-run --policy policy.kdl --audit-log /tmp/audit.jsonl \
    --report /tmp/report.json -- /path/to/connect_probe
```

Missing kernel support **skips** the e2e tests — a skip is the command's
own refusal path mirrored, never a pass-by-absence.
