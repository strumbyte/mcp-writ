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
| Report honesty | `--report` JSON carries `capability` (mechanism, kernel, per-namespace booleans incl. `pidns`), `child_sandbox` (`landlock_seccomp=applied`, `socket_family_narrowing=relaxed-namespaced`), `data_plane` per-protocol dispositions, `egress_layers` rule table with `proto`/`port`/`name_layer`/`ip_layer`, live `proxy_stats`, and the fixed `limitations` list |
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
  `connect`.
- **Shared-host reachability is policy-defined.** The netns makes
  host-IP egress impossible, but a name/IP that resolves to a *host*
  daemon (e.g. a LAN service) is relayed if the policy allows it.
- **Userspace stack is the boundary.** A smoltcp/proxy bug is a
  boundary bug; bounds exist for flows, counters, and packet size —
  abnormal-input fuzzing beyond malformed-packet drops is not
  exercised.
- **No rate limiting.** Bounded counters exist; CPU exhaustion in
  the proxy is a recorded gap.

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
- Proxy/gate kill under active traffic (the TUN fd closes with the
  parent; workload teardown is verified, mid-flow behavior is not
  separately exercised)
- `git log`-committed runnable fixture: the manual commands and
  policy above are the reproduction recipe; a `cargo test` harness is
  future work

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
