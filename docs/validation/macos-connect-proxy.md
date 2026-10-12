# macOS `macos-proxy-run` PoC validation (improvement plan PR-11)

Real-machine verification of the loopback CONNECT-proxy route:
`mcp-writ macos-proxy-run` spawns a workload under `sandbox-exec` with
an SBPL profile whose only outbound TCP endpoint is a loopback CONNECT
proxy in the launcher process; the proxy evaluates the policy's
name/IP destination rules per CONNECT and dials outward itself.

Status: **verified on the reference host** — recorded 2026-10-10 ·
PR-11 working tree · macOS 26.6.2 (build 25G83) arm64,
`sandbox-exec` at `/usr/bin/sandbox-exec`. This is a **PoC**: it is
opt-in (`macos-proxy-run` only) and the product `run`/`plan` paths are
unchanged — `plan` still reports the macOS egress layers as
Auditor-only outside this command's own `--report`.

## Environment and mechanism gate

The route compiles on every platform for CLI/help parity but runs only
on macOS (`mod imp` is `cfg(target_os = "macos")`; elsewhere it exits
1 with a diagnostic). On macOS the hard prerequisite is
`/usr/bin/sandbox-exec` — helper validation, listener bind, profile
build, and spawn all refuse before launch; a route that cannot start
never falls back to the `sandbox-exec`-only path.

## SBPL reach experiments (real host, this machine)

The spec's open question — how much of destination control SBPL can
express natively — was settled by loading probe profiles:

| Probe | Result |
|---|---|
| `(remote tcp "localhost:PORT")` | accepted — the pin this route uses |
| `(remote tcp "*:PORT")` | accepted — port-only pin to **any** destination exists but is not used (it cannot express per-destination rules) |
| `(remote ip "ADDR")` / literal-IP `remote tcp` | **rejected at profile load** — "host must be * or localhost". IP-literal egress is not expressible in SBPL on macOS 26 → the proxy is required |
| `(remote udp "localhost:PORT")` | accepted — datagrams reach a loopback listener (verified with a python sender/receiver pair; an earlier "drop" was a listener-startup race) |
| `(local udp "localhost:*")` | accepted — UDP inbound can be pinned to loopback sources |
| `com.apple.mDNSResponder` denied | `getaddrinfo` dies silently inside the sandbox (`dscacheutil` returns nothing) — proxy mode relies on this |
| UDP `dig` under filtered outbound | needs `network-inbound` for the reply path — irrelevant here: proxy mode denies UDP outright instead |

## What was exercised

`cargo test --locked --test macos_proxy_e2e` (9 tests, all executed —
none skipped — on the reference host) plus the `macos_proxy` /
`macos_sandbox` ConnectProxy unit tests in `cargo test --lib`.
Coverage mapped to the PR-11 tasks:

| Spec item | Evidence |
|---|---|
| SBPL pins outbound TCP to the proxy only | `workload_direct_and_loopback_egress_is_kernel_denied` — direct connect to the host-interface echo listener and to another loopback port both fail inside the sandbox; only `localhost:<proxy>` answers |
| CONNECT authority → name-layer verdict | `proxy_denied_name_audits_name_layer` — `deny host=` on the CONNECT name refuses and commits `sandbox.network_denied` with `layer=name` |
| CONNECT literal/resolved → IP-layer verdict | `proxy_denied_cidr_audits_network_denied` — `deny cidr=` refuses with HTTP 403 after committing `sandbox.network_denied` `layer=ip` `decision=deny-cidr`; `proxy_allowed_connect_relays_and_audits` — `allow cidr="IP/32"` permits the dial and commits `sandbox.network_allowed` `layer=ip` |
| Proxy dials outward, payload never inspected | `proxy_allowed_connect_relays_and_audits` — `200` then `PING`→`PING-BACK:PING` echo splice; `proxy_relays_pipelined_bytes` — bytes already in the CONNECT request head's tail are forwarded, not dropped |
| `sandbox.network_denied` on refusal | the deny tests assert the committed JSONL record — deny-cidr: `layer=ip`, `dest`, `port`, `decision=deny-cidr`; protected-dest: `decision`, `dest`; deny-host: `layer=name`, `name`, `decision` |
| Proxy cannot be turned into an SSRF relay | `proxy_loopback_target_is_protected_denied` — `CONNECT 127.0.0.1:<echo>` is refused despite an `allow cidr=127.0.0.0/8` rule; protected destinations are rejected before policy evaluation |
| Per-launch credential | `proxy_missing_credential_gets_407` — CONNECT without the injected `Proxy-Authorization` gets `407` and the `denied_auth` counter |
| UDP + in-sandbox DNS stay denied | `workload_udp_and_dns_are_denied` — `sendto` to `192.0.2.1:53` raises `OSError` inside the sandbox, and `getaddrinfo` fails (mDNSResponder Mach lookup ungranted) |
| Capability/status report | `proxy_allowed_connect_relays_and_audits` asserts `--report` content: `component=macos-proxy-run`, `capability.mechanism=sbpl-loopback-connect-proxy`, `state=stopped`, `proxy_stats.accepted`, the layered egress table |
| Native path unaffected | `native_run_path_unaffected_by_proxy_opt_in` — `run --dry-run` behaves exactly as before the opt-in existed |
| Early-exit ambiguity (native parity) | the workload legs above exit inside the liveness window; the command records the workload's own exit status rather than misclassifying it as a spawn rejection — the semantics the native path documents |

Unit coverage in `cargo test --lib` (warden + macos_proxy): CONNECT
request-line parsing, malformed head rejection, hostname/IPv4/
bracketed-IPv6/bare-IPv6 target parsing, invalid/missing/zero ports,
userinfo and empty targets, case-insensitive `Proxy-Authorization`,
Basic credential shape, request-head bound, pipelined-payload
preservation, protected-destination detection, and the proxy-mode
SBPL shape (loopback pin, no blanket `network-outbound`, mDNSResponder
Mach lookup absent, policy-declared `localhost:port` rules still
emitted, CIDR/remote-host entries recorded as proxy-enforced vs
skipped, native mode unchanged).

Regression sweep on the same tree: `cargo test --locked` full suite
1968/1968; `cargo test --locked --test macos_proxy_e2e` 9/9.

## Recorded limits (kept in `--report.limitations`)

- **TCP only.** CONNECT has no UDP equivalent — the profile denies all
  UDP egress; a UDP-capable allow rule is unenforced (warned).
- **Proxy-env cooperation.** A workload that ignores the injected
  `http_proxy`/`https_proxy`/`all_proxy` vars has no egress at all —
  fail-closed, but applications without proxy support cannot egress.
- **Trusted proxy task.** The proxy runs in the launcher process; a
  launcher compromise voids the mechanism. For a boundary that does
  not trust the supervisor, Apple Container's VM/NAT isolation is the
  documented stronger route — the host-side gate is a separate
  backend design, not implemented in this PR.
- **Credential scope.** A host process that learns the per-launch
  token could use the proxy listener; it is a piggyback guard, not an
  authentication boundary against a hostile co-resident.
- **Kernel denies are silent.** A direct `connect` the profile refuses
  leaves no audit record — only proxy-evaluated refusals emit
  `sandbox.network_denied` (same observation gap as the native path).
- **Minted-grant TTL cap.** `getaddrinfo` returns no TTLs; name→IP
  grants the proxy mints live at most 5 minutes. The DNS gate's
  answer-accurate TTLs remain the stronger mechanism where it runs.
- **`sandbox-exec` is deprecated** — no kernel acceptance signal; this
  route adds a proxy and does not strengthen the boundary.
- **No fallback** — an unstartable route refuses rather than
  substituting the `sandbox-exec`-only path.

## Reproduce

```bash
cargo test --locked --test macos_proxy_e2e            # 9 tests; skips without sandbox-exec/python3/interface
cargo test --locked --lib warden::                    # profile + proxy unit tests
mcp-writ macos-proxy-run --policy policy.kdl --audit-log /tmp/audit.jsonl \
    --report /tmp/report.json -- /usr/bin/python3 tests/fixtures/macos_proxy/connect_probe.py \
    <host-ip>:<echo-port>
```

Missing prerequisites **skip** the e2e tests — a skip mirrors the
command's own refusal path, never a pass-by-absence;
`MCP_WRIT_REQUIRE_E2E_TESTS=1` fails the skip instead.
