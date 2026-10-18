# Linux `namespaced-run` PoC validation (improvement plan PR-09)

Real-kernel verification of the namespaced egress path: `mcp-writ
namespaced-run` launches a workload inside a **user + network + mount +
pid namespace** created without any host capability, gives the network
namespace nothing but a TUN device, and relays traffic through an
in-process userspace proxy that evaluates every flow against the
policy's static CIDRs, `proto`/`port` qualifiers, DNS-gate name rules,
and TTL-scoped dynamic grants. DNS is intercepted inside the namespace
by the embedded gate; `resolv.conf` is bind-mounted inside the private
mount namespace so the host file is never touched.

Status: **verified on the reference host** — recorded 2026-10-10 ·
PR-09 working tree · WSL2 on Windows 11, kernel
`6.18.40.1-microsoft-standard-WSL2`, x86-64, `rustc`/`cargo` 1.99.0.
This is a **PoC**: it is opt-in (`namespaced-run` only) and the product
default `run`/`plan` paths are unchanged.

## Capability gate (probe before launch)

`namespaced-run` probes by performing the real operations in a
throwaway grandchild before any launch — unshare
(`CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS`), parent-side
`uid_map`/`gid_map`/`setgroups` writes, TUN creation (`/dev/net/tun`),
loopback-up, and a default route over the TUN — then reaps it. All
succeeded on the reference kernel:

```
userns=true netns=true mountns=true id_map=true tun=true
loopback_up=true route=true
```

Failures are reported with a distinguishing stage — probe
(`unshare` / `fork` / `idmap` / `tun` / `loopback` / `route`) or the
init handshake's `ERR <stage>` (`fork-pipe` / `unshare` / `idmap` /
`tun` / `net` / `pidns-fork` / `proc-mount` / `sandbox policy-load` /
`exec`) — the launch is refused, and no host state is changed
(verified: host `/etc/resolv.conf`, `/run`, and interface list
unchanged after runs; no `egress0` exists on the host).

## What was exercised

All legs ran the real `mcp-writ namespaced-run` binary with
`--policy`, `--upstream 1.1.1.1`, `--audit-log`, and `--report`.
Policy sketch (full file under `.local/pr09-test/policy.kdl`):

```kdl
network {
    allow host="1.1.1.1" proto="tcp" port=443
    allow host="1.1.1.1" proto="tcp" port=80
    allow host="172.21.248.189" proto="udp" port=8081
    allow host="one.one.one.one" proto="tcp" port=443
    deny host="*"
}
```

| Spec item | Evidence |
|---|---|
| Non-privileged userns+netns+mountns(+pidns) launch; id-map without host caps | every leg; workload observed itself as `uid=0` inside the userns mapped to the launcher's euid; `--report.capability.namespaces` all `true`. Note: self-written id-maps are EPERM on WSL2, so the init parent writes `/proc/<pid>/{setgroups,uid_map,gid_map}` for the grandchild — the only unprivileged mapping path |
| TUN-only egress; FD handed to host proxy via `SCM_RIGHTS` | workload `/proc/net/route` shows only `egress0` (default + link subnet); all flows traverse the parent proxy (proxy counters move); workload fd list = `0 1 2 3` (fd 3 is its own) — handshake socket, policy memfd, and TUN fd never reach it |
| TCP allow | `curl https://one.one.one.one/` → `HTTP 200` through DNAT → smoltcp → backend splice (`tcp_accepted=1`, 63 KiB relayed on the longer leg); `curl http://1.1.1.1/` → `HTTP 200` |
| TCP deny + audit | `curl https://9.9.9.9/` → connection reset, `tcp_denied=1`; audit: `sandbox.network_denied` `layer=ip proto=tcp dest=9.9.9.9 port=443 decision=not-allowed` |
| UDP allow / per-datagram / unconnected | python `sendto` to a host echo server → `b'echo:hello-udp'`, second datagram `b'echo:second'` (`udp_flows=1 udp_datagrams=3`); unconnected socket used, so `sendto`-style destination-per-datagram is the exercised path |
| UDP deny + audit | `sendto` to a non-allowed IP/port → timeout (silently dropped at relay), `udp_denied=1` |
| DNS gate intercept + dynamic grants | `getent ahostsv4 one.one.one.one` resolves via `nameserver 10.250.0.1` (bind-mounted resolv.conf); audit `sandbox.network_resolved` `layer=name ... qtype=A rcode=noerror addrs=[1.1.1.1,1.0.0.1] grants=2` — grants are installed before the answer returns, and the following HTTPS connect passes the IP layer |
| DNS deny | `evil.example.com` query → `rcode=refused`; audit `sandbox.network_denied` `layer=name name=evil.example.com decision=not-allowed` |
| Deny precedence / default-deny | `deny host="*"` tail is honored for both layers; unmatched TCP reset, unmatched UDP dropped, unmatched names refused |
| `proto`/`port` qualifiers end-to-end | `allow host="1.1.1.1" proto="tcp" port=443` parsed into `EgressRule`, surfaced in `--report.egress_layers.rules` with `proto`/`port` columns, evaluated by the proxy; Landlock keeps `ConnectTcp` narrowing only when every TCP-covering allow is port-qualified — otherwise delegated to the proxy rather than widened |
| Bare-port bug (PR-08 fix) | `allow host="443"` now parses as a port rule (`bare_port_spelling`), not a bogus `0.0.1.187` literal — unit-covered in `host.rs`/`kdl_parse` tests |
| IPv6 | `disable_ipv6=1` inside the netns; the proxy drops any v6 datagrams anyway (`dropped_non_v4` counted — observed `1` per run, the kernel's own v6 chatter) |
| Non-TCP/UDP protocols | raw `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` → `PermissionError` at creation (no ping-group-range entry in the userns); the proxy would also drop proto ≠ 6/17 (`dropped_proto`) |
| Fragments | dropped at the classifier (`dropped_fragment`); no reassembly by design — recorded in `limitations` |
| Monitor-interference | `CLONE_NEWPID` + a second fork makes the workload pidns init: `/proc/self/status` shows `Pid: 1`, `/proc` remounted private lists only `1` — the supervisor is unobservable and unsignalable |
| `setns` / nested `unshare` / `io_uring` | `os.setns` → EPERM, `unshare(CLONE_NEWNET)` → −1, `syscall(425)` (`io_uring_setup`) → −1 — none are in the workload's syscall policy; `io_uring_*` also sits on the dangerous-syscall list so even an explicit grant is surfaced |
| Host AF_UNIX proxying | `connect('/run/dbus/system_bus_socket')` **succeeded before the fix** — closed by mounting a private tmpfs over `/run` (covers `/var/run` symlink); now `FileNotFoundError`. Socket paths outside `/run` remain fs-policy territory and are reported as a limitation |
| Supervisor death | `SIGKILL` on `mcp-writ` while a `sleep 30` workload ran → `PR_SET_PDEATHSIG` cascade (init → grandchild → pidns init) reaped the whole subtree; `ps` shows no leaked init or workload processes |
| Route self-harm | workload is ns-root with `CAP_NET_ADMIN` over *its own* netns — it could re-point routes, but every route still lands on `egress0` (the only non-lo device); a `link set down` merely kills its own egress — fail-closed, recorded |
| Report honesty | `--report` JSON carries `capability` (mechanism, kernel, per-namespace booleans incl. `pidns`), `child_sandbox` (`landlock_seccomp=applied`, `socket_family_narrowing=af-inet-af-inet6-allowlist`), `data_plane` per-protocol dispositions, `egress_layers` rule table with `proto`/`port`/`name_layer`/`ip_layer`, live `proxy_stats`, and the fixed `limitations` list |
| Exit-status forwarding | workload exit code propagates through pidns-parent → grandchild → init → supervisor (`sleep`/exit-code legs, plus `signal` re-raise on signal death) |

Regression sweep on the same tree: `cargo test --lib` **1958/1958**,
`cargo clippy --all-targets -D warnings` clean, `cargo fmt --check`
clean.

## Performance (cold/warm vs native)

| Measurement | Value |
|---|---|
| `namespaced-run -- true` (warm, ×3) | 0.22 s, ~16 MiB maxrss |
| `mcp-writ --version` (baseline) | 0.04 s |

Per-launch overhead ≈ 180 ms + ~16 MiB — namespace setup, TUN
bring-up, and policy memfd load. First-flow latency is dominated by
the DNS round-trip; the proxy adds user-space copies only (no sleep
or retry in the path).

## Recorded limits (kept in `--report.limitations`)

- **IPv4 only.** IPv6 is disabled in the child netns and dropped at
  the proxy — fail-closed, not a bypass.
- **No fragment reassembly** — fragmented datagrams are dropped.
- **TCP evaluated at accept; UDP per datagram.** A TTL grant expiring
  mid-flow stops later UDP datagrams immediately; an already-accepted
  TCP connection keeps its verdict until close (spec'd behavior —
  live TTL-expiry-mid-TCP not exercised; upstream TTLs are minutes).
- **DoT/DoH gap.** Encrypted DNS to an allowed destination is
  indistinguishable from ordinary TLS — name-layer enforcement needs
  plaintext DNS; IP/CIDR rules still apply.
- **`/run`-external AF_UNIX.** Host socket paths outside `/run` are
  hidden only by the fs policy — Landlock does not mediate AF_UNIX
  `connect` below ABI v9 (kernel 7.1, `AccessFs::ResolveUnix`), so the
  in-namespace socket-family pin is the boundary that actually closes
  this leg on every kernel the route supports.
- **Shared-host reachability is policy-defined.** The netns makes
  host-IP egress impossible, but a name/IP that resolves to a *host*
  daemon (e.g. a LAN service) is relayed if the policy allows it.
- **Userspace stack is the boundary.** A smoltcp/proxy bug is a
  boundary bug; bounds exist for flows, counters, and packet size —
  abnormal-input fuzzing beyond malformed-packet drops is not
  exercised.
- **No rate limiting.** Bounded counters exist; CPU exhaustion in
  the proxy is a recorded gap. Queueing is bounded everywhere (a
  full channel drops packets rather than growing memory) and the
  per-datagram audit path is deduplicated plus budget-capped —
  suppressed emissions are counted in `proxy_stats.udp_audit_suppressed`.

## Acceptance matrix — not yet exercised (kept unverified per spec)

- `sendmmsg` with mixed destinations in one call (the per-datagram
  path is identical — each datagram is looked up by its own
  destination — but a dedicated multi-destination fixture was not
  run)
- QUIC with a real HTTP/3 client (UDP destination control treats it
  uniformly; no HTTP/3 client was available on the host)
- TTL expiry *while* a TCP connection is open (upstream TTLs exceed
  practical test duration; the spec'd behavior is recorded above)
- Grant isolation across two concurrent sessions
- IPv6 extension-header packets and crafted fragmentation

## Files

- `src/warden/namespaced/` — `init` (namespace setup, id-map fork
  dance, resolv.conf + `/run` mounts, pidns + `/proc`, pdeathsig
  cascade, fd scrub), `spawn` (socketpair handshake, `SCM_RIGHTS`),
  `probe`, `netlink`, `stack` (TUN reader, smoltcp loop, TCP splice,
  UDP relay, DNS intercept), `nat`, `eval`, `report`
- `src/commands/namespaced_run.rs` — CLI orchestration (`namespaced-run`)
- `src/warden/landlock_impl.rs` — `create_landlock_ruleset_namespaced`
- `src/dnsgate/` — `QueryCore` reuse for the embedded gate; quals-aware
  grants
- `src/policy/` — `EgressRule` (host/proto/port), `bare_port_spelling`,
  parse/emit/merge/export coverage

## PR-16 product integration — `run`/`plan` mechanism selection

Recorded 2026-10-16 on the same host (WSL2 Ubuntu 24.04 x86-64, kernel
6.18.40.1-microsoft-standard-WSL2, rustc/cargo 1.99.0, working tree
uncommitted). The PR-09 PoC stack is now the productized Linux egress
route: `run --linux-mechanism auto` prefers it when the launch-time
probe passes and the policy is fully satisfiable, `namespaced` pins it,
and `native`/`auto` fall back only to a native route that demonstrably
satisfies the policy — never silently, never after a namespaced
failure.

### Selection matrix exercised (`plan --linux-mechanism <m>`)

| Policy ↓ / Request → | `auto` | `namespaced` | `native` |
|---|---|---|---|
| deny-all (no egress rules) | `linux-namespaced` | `linux-namespaced` | `linux-native` |
| TCP `allow host=1.1.1.1 port=443` | `linux-namespaced` | `linux-namespaced` | **refused** — dest-scoped allow is inexpressible on Landlock netport |
| TCP `allow host=example.com port=443` | `linux-namespaced` | `linux-namespaced` | **refused** — name-layer requirement |
| UDP `allow host=8.8.8.8 proto=udp port=53` | `linux-namespaced` | `linux-namespaced` | **refused** — UDP allow is a dead policy on native |
| IPv6 `allow cidr=2001:db8::/32 port=443` | **refused** — neither satisfies | **refused** — never falls back | **refused** |

The `auto`-with-namespaced-unavailable rows (probe failure → native
when satisfiable, refusal when not) are covered by the `warden::select`
unit tests — simulating a genuinely incapable host on this machine is
not possible without a second kernel.

### Live `run` legs

- `run --linux-mechanism namespaced --policy <fs+syscall+egress> --
  /bin/echo` → exit 0, `plan.mechanism.selected="linux-namespaced"`,
  `sandbox_applied=true`, `proxy_lost=false`.
- Python inline probe over TCP/UDP/DNS: `tcp_accepted=2`,
  `tcp_denied=1` with `sandbox.network_allowed`/`network_denied`
  records carrying `layer=ip`, `proto`, `dest`, `port`, and the matched
  rule; `udp_flows=1`, `udp_datagrams=3`, `udp_denied=2`;
  `dns_queries=3` with the injected `resolv.conf` returning
  `nameserver 10.250.0.1` and a denied name producing
  `Temporary failure in name resolution`; `dropped_non_v4=1`,
  `dropped_packets=2`.
- `run --linux-mechanism native` on `allow host=1.1.1.1 port=443` →
  launch refused at the `policy` stage (`native: launch refused — the
  policy exceeds what the native Landlock+seccomp route can satisfy`);
  the report carries `mechanism.requested="native"`, `selected=null`,
  the violation text, and the probe booleans.
- `run --linux-mechanism namespaced` on the IPv6 policy → refused with
  `namespaced: launch refused … never falls back to native`.
- Evidence agreement: `plan`'s `plan.mechanism`, `--report`'s
  `plan.mechanism` plus `target.native_linux_mechanism`/
  `sandbox_mechanism`, and the JSONL `policy.loaded` /
  `sandbox.network_*` records all derive from the same verdict.

### Fixes the integration surfaced

- Injected `resolv.conf` was unreadable: the private tmpfs bind-mount
  is not covered by `/etc/**` Landlock grants — a runtime `resolv-conf`
  grant scoped to the injected inode was added (`landlock_impl`).
- `namespaced-run` duplicated the policy memfd builder — switched to
  the shared `namespaced::policy_memfd`.
- Proxy teardown raced audit logger shutdown (`channel_closed` commit
  loss on the final denied-flow record) — `RunningChild` now quiesces
  the proxy (abort + await) before audit teardown on every exit path.
- `mcp-writ capability-matrix` regressed at CLI level: the `check`
  subcommand's `Cmd::take` was appended after `capability-matrix`, and
  noargs' last-taken-cmd check made a bare `capability-matrix`
  invocation fail with `command is not specified`. The take order is
  now fixed so `capability-matrix` is last (documented in
  `cli/mod.rs`).

### §1.7 residual-risk re-evaluation (PR-16 acceptance)

- **Proxy reliability** — unchanged assessment: the userspace stack is
  part of the boundary; bounded tables/counters, counted drops, and
  fail-closed teardown hold. A dead proxy while the workload lives is
  detected (`wait_for_natural_exit` → `SupervisionLost`) and kills the
  workload — now exercised end-to-end: PR-26's
  `tests/linux_mechanism_e2e.rs` ends the proxy task mid-`udp-loop`
  via the `MCP_WRIT_NS_PROXY_KILL_AFTER_MS` test hook (supervisor env,
  never forwarded into the namespace, and read only under
  `debug_assertions` — release binaries carry no kill switch) and
  asserts the workload is
  killed, `run` exits 1, `mechanism.namespaced.proxy_lost=true`, and
  the audit closes with `reason=supervision_lost`.
- **DoH / ECH / hardcoded resolvers** — unchanged: while a DNS
  upstream is configured, port-53 UDP/TCP is intercepted whatever
  destination the workload picks (a destination-scoped `:53` allow is
  refused at selection as dead policy); with no upstream there is no
  gate and :53 falls to the ordinary evaluator. Encrypted resolvers
  bypass only the name layer, IP rules still apply.
- **Shared IP** — unchanged: a DNS grant names the literal resolved
  address; disclosed in `limitations` and guide §8.3.
- **New boundary noted**: `auto` selection itself adds no new bypass —
  the verdict is computed from the same probe the launch performs, and
  an unsatisfiable combination refuses rather than degrading.

## PR-26 — committed `cargo test` harness (`linux_mechanism_e2e`)

Recorded 2026-10-18 on the same host (WSL2 Ubuntu 24.04 x86-64, kernel
6.18.54.1-microsoft-standard-WSL2, rustc/cargo 1.99.0, working tree
uncommitted). `tests/linux_mechanism_e2e.rs` turns the manual `run`-side
legs above into a committed target — registered in
`.github/workflows/linux-tests.yml` under
`MCP_WRIT_REQUIRE_E2E_TESTS=1` and listed in `docs/test-matrix.md`.
Workload fixture: `tests/fixtures/namespaced/net_probe.rs` (plain
`rustc`, `SocketAddr` literals only — hostnames and arity violations
are deterministic usage failures, never resolved or defaulted);
compile/run scratch lands under `target/linux-mechanism-e2e/` because
init masks `/tmp` and `/run` (a grant naming them is a selection
violation, not a dead mount).

Legs, all asserted against the real `run` binary's exit code,
`--report`, and audit JSONL:

| Test | Verdict |
|---|---|
| `auto_selects_namespaced_for_udp_policy` | `requested="auto"` → `selected="linux-namespaced"`; `udp-two` — allowed echo + dropped denied datagram; `udp_datagrams>=1`, `udp_denied>=1`, `sandbox.network_allowed`/`network_denied` records |
| `namespaced_tcp_allow_and_deny` | `tcp-two` — allowed flow spliced to the host echo; denied leg kept the granted *port* on a different host so it passes the in-ns Landlock netport rule and dies at the proxy evaluator (`tcp_denied>=1`, `dest=203.0.113.9` deny record) |
| `run_default_is_auto_and_prefers_namespaced` | no flag → `requested="auto"`; even a native-satisfiable `allow host="*" proto=tcp port=N` selects `linux-namespaced` |
| `native_refuses_udp_allow_before_spawn` | exit 1, `selected=null`, `result.status="failed"`, refusal detail names the dead-policy UDP allow; no `server.connected` in the audit |
| `namespaced_refuses_unsatisfiable_policy_without_fallback` | `allow "/run/…"` masked-tree grant → exit 1, `selected=null`, "masked tree" refusal on stderr; no `server.connected` |
| `proxy_loss_during_active_udp_traffic_kills_workload` | `MCP_WRIT_NS_PROXY_KILL_AFTER_MS=3000` ends the proxy mid-`udp-loop` (`NETPROBE-HB` on stderr proves live traffic, `udp_datagrams>=1`); workload killed, `run` exits 1, `proxy_lost=true`, `result.status="failed"`, audit `reason=supervision_lost` |

Result: `MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --test
linux_mechanism_e2e` — 6/6 passed (plus the shared `common::tests`
helpers in the same target).
