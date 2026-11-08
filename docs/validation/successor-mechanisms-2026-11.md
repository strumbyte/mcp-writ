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
  `.local/pr11-mxc/` (probe outputs; durable probe sources under
  `.local/pr11-mxc/src/` — `mxc-probe/`, `winiso-copy/`, `dl.rs`,
  `ll.py`).
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
| network destination | direct egress `default` + `allow[]`/`deny[]` of `cidr`+`protocol`+`port` — enforced on **non-local** destinations (v4+v6, allow/deny/`except` all work); **all host-local addresses (loopback + every interface IP, v4+v6) are exempt — gated all-or-nothing by `ingress.host_loopback`**, which despite its name covers `192.168.x`/`172.21.x`/ULA addrs too; **`UDP` is unmediated entirely — deny-all, deny rules, and proxy mode all leave UDP egress open (delivery verified).** `runtimeConfig.networkProxy` mode measured: raw TCP egress fail-closed except the proxy endpoint; destination scoping moves to the proxy layer | **no authorization event for IP networking** — cannot express allow/deny | v10 `LANDLOCK_ACCESS_NET_BIND_UDP` + `CONNECT_SEND_UDP` — **port-scoped only, never address-scoped** (same model as TCP since v4); mediates unconnected `sendto`/`sendmsg` destinations as implicit connects |
| syscall | container-side seccomp surface is OS-managed; no caller knob measured | — | — (orthogonal; warden's seccomp baseline stays regardless) |
| IPC | object namespace is private: host `Local\` **and** `Global\` mutex/event/file-mapping all `Open*`→`err:2` (invisible); own `CreateMutex` `ok`; **named pipes bounded too** (host pipe + `\\.\pipe\lsarpc` → `err:5`, own pipe creatable) — measured | auth for unix-domain IPC + macOS-27 XPC/bootstrap ops | v6 scoping (abstract unix, signals) already ≥ our baseline; v9 named-unix connect is the last relevant item (already handled) |
| process | grandchild spawn measured `ok` — inherits fs/net/reg policy (fs `err:5`, egress `10013`), fresh per-process AC SID, tree dies with the container | auth for exec/process controls; caller+descendants **cannot exec setuid/setgid** unless euid 0 | v8 `TSYNC` (process-wide enforce) / v11 `NO_NEW_PRIVS` flag — cosmetic for our child-launch model (already `prctl`) |
| audit/observability | `CaptureDenials` (Learning Mode) measured: `metadata.capture_denials` reports `output_path`/`exit_code`/`total_denials`/`denied_resources_truncated`; JSON per denial = `resource`+`resourceType`+`accessType`+`pid`+`filetime` | notify+auth events for the whole subtree — strong observability within scope | v7 audit logging, v10 quiet flag, v11 tracepoints — audit-relevant deltas worth tracking |

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
- `Containment::IsolationSession` (behind the `isolation_session`
  cargo feature) was exercised this round — see the dedicated section
  below; it cannot express warden policy (disqualified).

### Measured behavior inside the container (winiso `attempts` battery)

- Token: `is_appcontainer=true`, IL 4096, per-run AppContainer SID —
  confirms BaseContainer layers on app-container machinery (same as
  PR-30's PSEC child).
- fs: `ro` read ok / write `err:5`; `rw` write ok; `denied` +
  `ungranted` read+write `err:5`; enumerate of granted dir ok.
  (Caveat: an "ungranted" path still reads when it sits *under* a
  granted parent — e.g. when the probe binary's own directory was
  auto-granted `ro`, `work\ungranted\ungranted.txt` read `ok`. Deny is
  default only outside every grant, as designed.)
- **fs baseline semantics (measured — not strict default-deny)**: the
  container's filesystem view is a *curated allow baseline*, not
  "deny all except grants". Readable out of the box: `C:\Windows`
  (files *and* enumeration), `C:\Program Files`,
  `C:\Users\Public`, `C:\Windows\...\etc\hosts`, the child binary's
  own directory (auto-granted — files under it that were never listed
  in the policy read `ok`). Denied by default: `C:\` and `C:\Users`
  roots, the user's profile tree (`Desktop`, `Documents`,
  `NTUSER.DAT` → `err:5`), `C:\ProgramData`, **other drives**
  (`D:\` tree → `err:5`), and system secrets even under a readable
  parent (`SAM`, `SECURITY`, `security\database` → `err:5`).
  `denied_paths` are robust against syntax tricks: `\\?\` prefix,
  alternate data streams (`file:stream`), forward slashes, and
  **junction traversal** (junction inside a granted dir → `C:\Users`
  still resolved to the denied target → `err:5`). The ambient surface
  is **read-only**: writes to `C:\Windows\Temp`, `C:\Users\Public`,
  `C:\ProgramData`, and ungranted paths under the exe dir all failed
  `err:5` — only explicit `readwrite_paths` yield write access
  (`fs-ambient-write.txt`). `enumerate_paths` (processContainer fs
  config) grants listing without content reads — `C:\Users` enumerated
  ok while `desktop.ini` read stayed `err:5`
  (`fs-enumerate-paths.txt`). So: user data and secrets stay protected
  and explicit denies cannot be path-spoofed, but the baseline
  *grants more reads than warden's strict default-deny model* —
  adoption must treat system-area reads as ambient, and must not
  assume "ungranted == unreadable" outside the curated set
  (`fs-default-deny.txt`, `fs-baseline.txt`, `fs-junction.txt`,
  `fs-drives.txt`).
- **fs grants + bypass battery (JSON legs, `leg-fs-*.txt`, `hl-bypass.txt`)**:
  explicit `readwrite_paths`/`readonly_paths` lift the baseline deny
  (rw on a denied-dir → write+read+enum ok; ro on a profile dir →
  content read ok); **`denied_paths` always wins over grants**
  (same path granted rw + denied → write `err:5`, no file created).
  Alias/bypass attempts all blocked: `CreateHardLink` to a denied
  file from a granted dir → `err:5`; `CreateSymbolicLink` →
  `err:1314` (privilege absent); `\\?\GLOBALROOT\DosDevices\...`
  → denied path gives `err:123` (blocked, distinct code) while the
  ambient-readable path still reads (consistent baseline);
  `\\.\PhysicalDrive0`/`\Device\Harddisk0\Partition0` → `err:5`.
  **Write+exec is allowed**: an exe the child writes into a
  `readwrite_paths` dir executes (`findstr` copy → ran; no
  code-integrity check — process container, not WDAC). Note the
  inherited win32k mitigation: grandchildren that link `user32`
  fail `0xC0000142` (`STATUS_DLL_INIT_FAILED`) — same root cause as
  the original node.exe failure; user32-free exes run anywhere.
  Grant granularity verified: **`denied_paths` works as a
  sub-path deny inside a granted parent** (`readwrite C:\scratch\w`
  + `denied C:\scratch\w\secret` → sibling `ok.txt` readable +
  `new2.txt` written while `secret\data.txt` read, `secret\new.txt`
  write, and `secret` listing all denied — `leg-subdeny.txt`), and
  **file-level `readonly_paths` grants work** (direct
  `CreateFile`/`fs::read` → `ok` — `leg-filegrant2.txt`).
- **env** (wire `process.env` = `KEY=VALUE` strings, +
  `process.inheritDefaultEnv`): `Some(vec)` is used verbatim —
  `WINISO_RO_DIR` seen `true` inside the child; `None` = backend
  default; `inheritDefaultEnv=true` layers caller entries over the
  default block. Closes PR-30's PSEC gap ("env block is not
  inherited") at the SDK contract level.
- **Default env = user PROFILE block via `CreateEnvironmentBlock`
  (bInherit=FALSE) — persistent user+system vars flow in, process
  locals do not — but persistent secrets still leak (measured,
  adoption-critical)**: `env:None` delivered the user's full
  registry-backed environment — a live `ANTHROPIC_AUTH_TOKEN`
  (stored as a persistent user variable) was readable inside
  (`default-env.txt`, `leg-env-inh.txt`). Warden MUST pass an
  explicit env map. `Some(vec![])` is rejected pre-launch with a
  diagnostic (`leg-env-empty.txt`): the OS requirement is
  **presence-only** for `SYSTEMROOT` + `LOCALAPPDATA` — any value
  satisfies validation, so the clean minimum is
  `{SYSTEMROOT=C:\Windows, LOCALAPPDATA=<granted-dir>}` + chosen
  vars (`leg-env-min.txt` — launches, shows only supplied vars).
- **OS-level env carve-outs in verbatim mode**: `LOCALAPPDATA` gets
  a `\Packages\sandbox.{guid}` suffix appended by the OS and
  `TEMP`/`TMP` are injected pointing there — the "verbatim" block
  is rewritten at container boundary. Consequence (useful): the
  per-container writable scratch can be steered into a granted dir
  by setting `LOCALAPPDATA` to it — the package dir lands under it
  (`leg-env-min.txt`: `LOCALAPPDATA=C:\scratch\w` →
  `...\w\Packages\sandbox.{id}`).
- **package dirs are NOT policy-exempt and NOT cleaned up
  (measured)**: under the default location
  (`%LOCALAPPDATA%\Packages\sandbox.{guid}\AC`) writes are
  **denied by the fs policy** — `echo > %LOCALAPPDATA%\x` and
  `echo > %TEMP%\x` both `アクセスが拒否されました`
  (`leg-la.txt`, `leg-la2.txt`). The env vars are just pointers
  governed by the same policy — scratch is writable only when it
  lands under a granted prefix (the steering trick above). On the
  host side, `sandbox.{guid}` package dirs **accumulate and are
  never removed** — 41 leftover dirs observed after the probe
  runs (each holding `AC\INetCache/INetCookies/INetHistory/Temp`
  skeletons). Nothing written by denied-policy children lands
  there, but the GUID churn is permanent host-side garbage and a
  marker trail of every run.
- egress: `default deny` + `allow {to cidr, port P}` verified in both
  directions — off-rule non-loopback `203.0.113.1:443` → `WSAEACCES
  10013`; a non-loopback allowed destination+port (host LAN IP
  `172.21.240.1:59111`, listener on `0.0.0.0`) → **connected**. CIDR+port
  rules are enforced as documented for non-loopback destinations.
- **host-address exemption (security-relevant, measured)**: the
  `ingress.host_loopback` bit is mis-named — it gates **every
  host-local address**, not just loopback. With `Allow`, a loopback
  port *outside* the egress allow rule connected, and so did closed
  ports on the host's own interface addresses `192.168.11.238`
  (Wi-Fi), `172.21.240.1` (WSL vEthernet), `[::1]`, and Wi-Fi ULA
  `fd04:…` — all returned `10061` (reached the host stack) even with
  *no* matching allow rule. With `host_loopback=Deny` the same
  addresses all returned `10013`. Same-*subnet* neighbours are NOT
  exempt (`172.21.255.254:80` → `10013` under deny). Consequence for
  the warden-proxy pattern: `host_loopback=Allow` opens **every
  service on every host IP**, not just `127.0.0.1` — under direct
  egress there is no port scoping for host-local destinations
  (`egress-hostaddr-exempt.txt`, `egress-v6-ula.txt`,
  `egress-local-exempt.txt`).
- **rule semantics (measured)**: `allow` port qualifiers *do* narrow —
  `allow{to:203.0.113.0/24, port:R}` still denied `203.0.113.1:443`
  (`10013`); `deny[]` rules work — `deny{203.0.113.0/24}` under
  `default=Allow` denied `203.0.113.1:443` while `192.0.2.1:443`
  passed the filter (`egress-deny-rule.txt`, `egress-port-vs-lan.txt`).
  `except` works too — `allow{to:0.0.0.0/0, except:[203.0.113.1/32],
  no ports}` denied `203.0.113.1:443` (`10013`) while `192.168.11.1:80`
  attempted normally (`egress-except2.txt`).
- **UDP egress is NOT mediated — confirmed hole (measured)**: with
  `egress.default=Deny`, UDP `sendto` *and* `connect+send` to
  `203.0.113.1:53`/`8.8.8.8:53`/`127.0.0.1:53` all returned `ok` while
  TCP to the same destination was `10013`. `deny{203.0.113.0/24}` did
  not stop it; `deny{to:0.0.0.0/0, ports:[udp:1-65535]}` did not stop
  it; `host_loopback=Deny` does not gate UDP either (host-address UDP
  still flows — the host gate is TCP-only); **proxy mode did not stop
  it** — UDP raw egress stays open where raw TCP is fail-closed. A
  host UDP listener confirmed real delivery (`udp-delivery-proof.txt`:
  `RX 1B from 127.0.0.1:60214`). SDK-side: `NetworkProtocol::Udp` maps
  to `PsecIpProtocol::udp` in the spec, so the *format* carries UDP
  rules — the tier-1 enforcement simply does not apply them
  (`udp-deny-all.txt`, `udp-deny-udp-range.txt`,
  `udp-deny-dest-udp.txt`, `udp-hostlb-deny.txt`, `udp-proxy-mode.txt`).
  IPv6 is affected identically (`::1:53` `sendto` → `ok`;
  `udp-v6.txt`). **In the tested configuration the hole was
  egress-only / unidirectional** — a bound container UDP socket
  received nothing: host-source datagrams to `127.0.0.1:62444` and to
  the wildcard `0.0.0.0:62445` listener (sent via the LAN address)
  both timed out undelivered (`leg-ipc2b.txt`). That result holds
  only for the tested MXC listener configuration; it does **not**
  prove inbound UDP is impossible in every configuration —
  `hostLoopback=allow` UDP inbound remains untested on the MXC path
  (on the direct PSEC child path with `host_loopback=1`, inbound
  datagrams were explicitly received, so the gate is
  transport-agnostic there). Consequence: any workload can exfiltrate
  over UDP regardless of policy in every tested posture; whether it
  can also *receive* datagrams depends on unverified host-loopback
  combinations — do not assume a one-way channel. Adoption still
  requires a UDP block outside ProcessContainer's rules (unverified
  whether the host offers one reachable from tier-1) or restricting
  use to policies that explicitly permit unrestricted UDP.
- **ingress / listeners (measured)**: a container child can `bind()`
  TCP `0.0.0.0:port` (and UDP sockets) and the **host can connect**
  when `host_loopback=Allow` — delivery confirmed both directions
  and via *both* host loopback and host LAN address
  (`host-connect-ok`, `ACCEPTED from 127.0.0.1`; `ing-lb` leg:
  lb-ok + lan-ok). `host_loopback=Deny` blocks the host→container
  connect too, so the bit is a **bidirectional host↔container
  gate**, not just "container→host loopback". The wire schema has
  only `ingress.{default, hostLoopback}` — **no rules field
  exists** (rejected as unknown field). `ingress.default=Allow`
  with `hostLoopback=Deny` produced **no measurable effect** —
  host-source inbound stayed undelivered, consistent with the
  source finding that T1 maps only `hostLoopback` into PSEC
  policy and `ingress.default` is **silently unmapped**
  (`ing-d`/`ing-none` legs: listener bound, no accept; default
  empty-ingress posture is fail-closed — no inbound). Whether
  `ingress.default` would matter for non-host sources (LAN peers
  — the container shares the host network stack) remains
  untestable from this host alone (`ingress-listen.txt`,
  `ingress-hostlb-deny.txt`, `leg-ing-*.txt`).
- **egress precedence + wire shape (measured)**: `to` is a list of
  `NetworkPeer{cidr, except}`; `ports` a list of
  `NetworkPort{port}` (bare strings/ints rejected). **Deny wins
  over allow** for the same destination
  (`allow{192.168.11.0/24:445}` + `deny{192.168.11.238/32}` →
  `.238:445` `10013`, `.10:445` allowed/timed-out,
  `104.20.23.154:80` `10013` — `leg-precedence.txt`), and
  allow-`except` carves exclusions inside a CIDR
  (`allow{192.168.11.0/24 except .238/32}` → `.238` `10013`,
  `.10` allowed — `leg-allow-except.txt`).
- **`allowed_proxy_peer` — fully validated end-to-end on the
  unprivileged T1 spec route; grant is (identity AND
  declared-endpoint) scoped** (the legs carried
  `runtimeConfig.networkProxy` → T1 emitted `proxy`+`peer` in-spec;
  the measured spec prerequisites are listed at the
  `NetworkPolicy.proxy` entry). The wire validator
  enforces the pairing — a proxy *without* `allowedProxyPeer`
  **requires** `hostLoopback=allow` (the broad gate); with the peer
  declared, `hostLoopback=deny` is accepted. The value must be a
  **named AppContainer profile** (or package family name) — a raw
  `S-1-15-2-*` SID string is rejected
  (`E_INVALIDARG`); `MXC-Loopback` is SDK-reserved. Negative side:
  anonymous host listener at the proxy endpoint times out — the
  check is enforced in-path. **Positive side**: a listener spawned
  under `CreateAppContainerProfile("mxc.probe.proxy")` +
  `SECURITY_CAPABILITIES` (unprivileged, `acspawn.rs`) was
  reachable (`127.0.0.1:61241` → connected), while `127.0.0.1:1`
  and the *same listener* via LAN IP `192.168.11.238:61241` were
  `10013`. **Port granularity measured**: a *second* listener under
  the **same peer identity** on port 61242 was `10013` — the grant
  is bound to the declared `networkProxy` **endpoint**, not merely
  the identity (`peer-ports.txt`). Effective rule: *TCP to the
  declared proxy address is permitted only when the remote process
  runs under the declared AppContainer identity* — the tightest
  possible host-access posture. Consequence: warden's proxy under a
  named profile confines all container host TCP access — both
  directions — to that one (identity, endpoint) pair.
- **Default network posture (no `network` block) is deny-by-default
  for TCP — corrected model**: `203.0.113.1:443`, `127.0.0.1:1`, and
  the host LAN IP all returned `10013` (`default-net.txt`).
  `host_loopback` defaults to *deny* — `dnscache` is unreachable,
  so **`example.com` fails `11001` while `localhost` resolves from
  hosts data** (`dns-default.txt`; earlier "DNS works" readings
  were under `hostLoopback=allow`). UDP is *still* fully open under
  this default (`udp-default.txt`). So the egress posture is a
  knob-granular default-deny for TCP, with UDP never mediated.
- **`capabilities` grants do not override the rule set (measured)**:
  `capabilities:["internetClient"]` under `egress.default=deny` +
  `hostLoopback=deny` still returned `10013` for non-local connects —
  capabilities grant traffic *classes*, WFP deny rules still apply
  (`cap-internetclient.txt`). `learning_mode:true` alone behaves like
  deny-and-record (explicit denies stayed `err:5`; `learning-mode.txt`).
- **ICMP blocked at API level (measured)**: `IcmpCreateFile` →
  `INVALID_HANDLE_VALUE`; no echo capability inside the container
  (`icmp.txt`).
- **named pipes are boundaries too (measured)**: container could not
  open a host-created pipe or `\\.\pipe\lsarpc` (`err:5`); creating
  its own `\\.\pipe\` server succeeded — NPFS honours the same
  isolation as the object namespace (`pipe-ipc.txt`).
- **remaining IPC/socket transports are all bounded (measured,
  `ipc2.rs`, `leg-ipc2*.txt`)**: AF_UNIX `bind()` inside the
  container → `WSAEACCES 10013`; `CreateMailslot` → `err:5` and a
  host mailslot open → `err:5`; raw `SOCK_RAW/IPPROTO_TCP` socket
  → `10013`; raw `SOCK_RAW/IPPROTO_ICMP` *created* but `sendto`
  fails `WSAEAFNOSUPPORT 10047` (unusable); **UDP inbound
  mediated** — datagrams to a bound container socket (loopback
  and wildcard listeners, host-source via LAN addr) never arrive.
  Combined with the pipe/object findings: the only socket-family
  egress that escapes policy is UDP *send*, and nothing inbound
  or IPC-shaped crosses the boundary.
- **`process.cwd` semantics (measured)**: `cwd` is optional and
  needs no fs grant for launch. An explicit denied cwd does not
  fail spawn — the child comes up in a fallback dir (`cmd /c cd`
  printed `C:\WINDOWS\System32` when asked to start in a denied
  path; `leg-cwd-*.txt`). When omitted, the SDK derives the
  working dir from the granted fs paths (launch log:
  `working directory: ... (from filesystem policy (process.cwd
  omitted))`). Wire field names on `process`: `commandLine`,
  `cwd`, `env`, `inheritDefaultEnv`, `timeout` (no
  `workingDirectory`).
- **fs-deny normalization bypass battery — all resisted (measured,
  `fs5.rs`, `leg-fs5.txt`)**: denied `C:\scratch\secretdir\secret.txt`
  under granted `C:\scratch` stayed denied through UPPER and mixed
  case (`err:5` — the matcher is case-insensitive), the 8.3 alias
  `SECRET~1` (`err:5`), trailing `.`/space (`err:5`), forward
  slashes (`err:5`), `.\` components (`err:5`), `\??\` NT prefix
  (`err:123`), `\\?\UNC\localhost\c$` (`err:65`). Combined with
  the earlier junction/ADS/`\\?\`/hardlink/GLOBALROOT results,
  every classic Windows path-normalization evasion class is
  covered.
- **token surface (measured, `tok.rs`, `leg-tok.txt`)**: tier-1
  children run at **integrity level Low** (`0x1000`) with
  `IsAppContainer=1` and `ElevationType=3` (default) — the PSEC
  identity still presents as an AppContainer-family token, below
  Medium IL (cannot write host Medium-IL objects).
- **socket-family sweep + self-loopback (measured, `fams.rs`,
  `leg-fams.txt`)**: `AF_INET6` sockets create fine (v6 UDP egress
  already proven open); `AF_BTH`/`AF_HYPERV` fail
  `WSAEPROTOTYPE 10041` and `AF_NETBIOS`/`AF_IRDA`/`AF_VSOCK`/
  `AF_IPX` fail `WSAEAFNOSUPPORT 10047` — OS-level absent, not
  policy-denied; INET/INET6 are the only meaningful families.
  **A container cannot connect to its own listener** — bind
  `127.0.0.1:62599` ok, connect to it `10013`. The loopback gate
  exempts nothing, not even self-identity: a warden sidecar proxy
  *inside* the same container is unreachable; the proxy must live
  outside as a declared peer (matches the existing design).
- **same-`containerId` siblings share nothing (measured)**:
  `containerId` is the wire name (root fields: `$schema`,
  `_comment`, `version`, `containerId`, `containment`,
  `lifecycle`, `process`, `filesystem`, `fallback`, `network`,
  `ui`, `appContainer`/`processContainer`, `lxc`,
  `macos_sandbox`, `seatbelt`, `runtimeConfig`, `telemetry`,
  `wslc`). Two spawns with identical `containerId` — listener A
  vs connector B — still got `10013` (`leg-sib-a/b.txt`). The
  network identity is per-spawn, not per-id (the same-id ⇒
  same-SID caveat is T2/T3 DACL-stamping only).
- **`windows_sandbox` is lifecycle-provision only in the stable
  contracts — but the dev contract reaches a real VM launch
  (measured)**: the stable `0.9.0-alpha`/`1.0.0` one-shot
  `containment` enums do not contain it; the dev `1.1.0-alpha`
  contract adds `vm`/`microvm`/`windows_sandbox`/`hyperlight`
  (plus a `windows_sandbox`/`hyperlight`/`test` root field and
  `OneShotWindowsSandbox`/`OneShotHyperlight` config structs).
  Under `version:"1.1.0-alpha"` + `experimental=true` the
  variants parse, but the streaming `spawn` dispatch rejects
  them ("does not yet support streaming"). The
  **run-to-completion** path (`mxc_engine::run`, `mxc-run.rs`
  driver) resolves `WindowsSandbox` → `WindowsSandboxRunner`,
  and on this host **actually launched a sandbox VM**: a
  `.wsb` config was staged under `%TEMP%\wxc-wsb\oneshot\{id}\`
  (host exe dir mapped RO to `C:\Sandbox-Guest`, a rendezvous
  folder mapped RW with `bootstrap.cmd` + `nonce.bin`,
  `LogonCommand=bootstrap.cmd`, `vGPU=Disable`,
  `Networking=Enable`) and a zygote-derived VM partition
  appeared (`vmmemWindowsSandbox` + its `vmwp`, parented by
  `vmmemCmZygote`). The host's `Containers-DisposableClientVM`
  feature is Enabled. **Caveats measured**: the guest never
  completed the rendezvous in ~15 min (no output returned;
  likely session/bootstrap-timing dependent — unverified), and
  **killing the caller leaves the VM running** — `vmwp` is a
  SYSTEM process unkillable non-elevated, so a one-shot caller
  crash orphans a live sandbox VM until Windows retires it
  (`leg-wsb-run.txt`, staging dir listing).
- **Other VM-tier backends measured**: `hyperlight` resolves but
  rejects "requires x86_64 (Hyperlight needs KVM or WHP)" — WHP
  unavailable on this host; `microvm` and `wslc` are
  feature-gated out of this build ("not compiled in",
  `--features microvm`/`wslc`). Windows Sandbox is the only
  VM-tier containment that reached a live launch here.
- **Full stable request surface (source-complete)**: `lifecycle`
  = `{destroyOnExit, preservePolicy}`; `telemetry` =
  `{enabled}`; `fallback` = `{allowDaclMutation}`;
  `processContainer.ui` = `{isolation, desktopSystemControl,
  systemSettings, ime}` (the last two untested — same "no
  measurable effect" class expected);
  `processContainer.captureDenials` = `{mode, outputPath,
  retainEtl}`; `processContainer.network` =
  `{allowedProxyPeer}`; `runtimeConfig` = `{networkProxy}`;
  `lifecycle`/`telemetry` are informational in one-shot.
- **CaptureDenials audit-event shape (measured, durable file)**:
  `{denials:[{resource, resourceType:file|ui|other,
  accessType:read|write|unknown, pid, filetime}]}` — e.g.
  `ConvertToGui` UI access, registry-hive reads, `*.mui` write
  attempts. Concrete audit-schema input for warden.
- **PSEC GA spec surface vs the matrix `windows-psec` entry —
  the deficiency list is a v1.0-schema bound, not an OS limit
  (spec + support-flags + runtime measured)**: the SDK's
  FlatBuffers `ProcessSecurityEnvironment` root carries
  `VERSION`, `CAPABILITIES`, `DISALLOW_WIN32K_SYSTEM_CALLS`,
  `UI_RESTRICTIONS`, `FS_READ_WRITE`, `FS_READ_ONLY`,
  `FS_DENY`, `FS_ENUMERATE`, `NETWORK_POLICY` — the *entire*
  policy in one blob. `NetworkPolicy` = `{PROXY(ProxyInfo.url),
  EGRESS(EndpointPolicy{default, allow[], deny[]}),
  ALLOWED_APPCONTAINER_PEER, INGRESS(IngressPolicy{default,
  host_loopback})}`; `EndpointRule` =
  `{DESTINATIONS(IpSubnet{address,prefix_length}),
  PORTS(PortRule{protocol, port, end_port})}` — CIDR prefixes,
  port ranges, protocol qualifiers, all native in the spec.
  `secenv.rs` gates `FileSystemEnumerate` and `NetworkIngress`
  on **v1.1**; `FileSystemDeny` is v1.0. Direct host probe
  (`secv.rs`, `secv-host.txt`):
  `QueryProcessSecurityEnvironmentSupport` → **flags=0xf**
  (FileSystemDeny + bit1 + FileSystemEnumerate +
  NetworkIngress all present) and
  `IsProcessSecurityEnvironmentVersionSupported(1)` →
  **available=1, minor=1** (spec v1.1; v2 absent). The matrix
  row's `IPv4 /32 literal only / no ports / no IPv6 / no
  ingress / no loopback exemption` describes warden's **v1.0
  encoder**, not the GA OS surface — a future mechanism upgrade
  emitting v1.1 fields would move `windows-psec` to:
  `os.net.outbound` gran `cidr+port+protocol` v4+v6 (UDP rules
  encodable but unenforced — measured hole stands),
  `os.net.inbound`/`os.net.loopback` via the hostLoopback gate
  + `allowedProxyPeer` identity scoping, `enumerate_paths`,
  proxy URL in-spec. Still absent at v1.1: destination *names*
  (no FQDN layer — proxy required, same as everywhere except
  linux-namespaced), CPU/memory limits, UDP enforcement.
- **Cross-OS destination-control gap map (matrix layers vs
  measured, synthesis)**: `linux-native`'s `ip` layer is
  **port-only** (`landlock netport`, TCP — no destination
  scoping at all); `linux-namespaced` is the only complete
  row (`tun-userspace-proxy`: fqdn + cidr/ip + proto + port,
  tcp+udp); `linux-ebpf` matches namespaced granularity
  (opt-in); `macos-sbpl` is loopback-port-only; `macos-connect-proxy`
  fills fqdn + cidr/ip + port TCP (UDP structurally denied);
  `windows-appcontainer` has **empty** layers (Auditor
  argument-checks only); `windows-psec` v1.0 emits
  literal-IPv4/32. **With the v1.1 fields this OS accepts, an
  upgraded `windows-psec` encoder would emit
  cidr+literal-ip+proto+port over v4+v6 — strictly stronger
  than linux-native (port-only) and equal to namespaced's IP
  layer modulo UDP** — the largest single-step gap closure
  measured in this study.
- **Concrete upgrade loci (repo)**: `src/warden/psec_spec.rs`
  encodes the FlatBuffers v1.0 spec; its header lists the
  deliberately-absent fields (`capabilities`,
  `ui_restrictions`, `disallow_win32k_system_calls`,
  `deny`/`except` endpoint forms, ingress rules, IPv6
  destinations) as "no evidence supports them on the measured
  build" — this host's GA measurements now supply that
  evidence (the encoder was written against the public
  *preview* `.fbs`; the SDK's generated layout is the GA-era
  schema). `src/policy/validator/psec.rs`
  `psec_ipv4_expressible` (`entry.parse::<Ipv4Addr>()`) is
  the load-time refusal for non-IPv4/non-/32; port qualifiers
  refuse in `build_launch_spec`. Upgrade = emit the v1.1
  fields + relax those two refusal sites. The encoder's
  transport-blindness rationale (a ports-less rule widens TCP
  allows to UDP) is **moot here** — UDP is unmediated
  regardless, so port-qualified rules cannot widen anything
  not already open.
- **Warden-side spec acceptance measured on this host**
  (`tests/fixtures/windows_isolation` probe, build
  26200.9711 — `contracts-9711.json`, `psec-spec-test-9711.json`,
  `psec-run-9711.json`): the repo's own PSEC path works
  end-to-end on the GA build — `psec-run` spawned a child
  (AC SID, IL 4096) with fs ro-read `ok` / ro-write `err:5`
  / rw-write `ok` / deny read+write `err:5`, net deny-by-default
  `10013`, registry writes denied, kill-on-close confirmed.
  `contracts` reports flags `0xf`, `v{1,minor=1}` available.
  The spec ladder accepts **every v1.1-era wire shape at
  `CreateProcessSecurityEnvironment`**: `minimal-ident-v1.1`
  (hr=0 — the reference host 26200.9457 returned
  `0x80070032` for the same bytes, so v1.1 acceptance is a
  **build boundary between .9457 and .9711**, not a "GA"
  constant — adoption must gate on
  `IsProcessSecurityEnvironmentVersionSupported` or the
  ladder, not the OS edition), plus a patched ladder:
  `net-allow-cidr24` (prefix 24), `net-allow-v6`
  (`fd00::1`), `net-allow-portrange` (`end_port` slot 2),
  `net-ingress-v11` (`IngressPolicy{default_action,
  host_loopback}`) — **all hr=0**, and accepted under the
  v1.0 version header too: the version field does not gate
  fields, the server parses what it knows. Acceptance ≠
  enforcement, but the SDK already measured runtime
  enforcement of these exact shapes through the same
  `processmodel.dll` — the warden-side unknowns are closed.
  Also resolved on this build: `Experimental_*` sandbox
  exports (`CompileSandboxSpecificationInternal`,
  `QuerySandboxSupport`, `CreateProcessInSandbox`) and the
  IsoSession Preview class — surfaces not present on the
  reference host.
- **`capabilities` is the gate in front of the egress rules —
  and warden's PSEC spec omits it, so its allow rules cannot
  fire on this build (measured)**: the spec root's
  `CAPABILITIES` field is a **comma-joined string** (slot 1),
  not a vector. `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`
  is **mutually exclusive** with `SECURITY_CAPABILITIES`
  (`src/warden/windows_proc.rs` 71-78) — on the PSEC path the
  spec field is the *only* source of token network
  capabilities. Direct measurement: a spec with
  `egress{default:deny, allow:[{10.20.30.0/24, tcp:61263}]}`
  and **no** capabilities → `connect(10.20.30.40:61263)` =
  `10013` (capability gate denies before rule evaluation);
  the identical spec plus `capabilities:"internetClient"` →
  `timeout` (policy passed, destination unreachable) while
  `10.20.31.40:61263` (outside /24) and `10.255.255.1` stay
  `10013` — **a warden-format spec with CIDR+port rules
  enforces at runtime** (`psec-run-caps-cidr24-9711.json`,
  `psec-run-v11-header-9711.json`; the v1.1 version header
  makes no difference). `src/warden/psec_spec.rs` omits
  `capabilities` deliberately → **the matrix `windows-psec`
  `os.net.outbound` row's `literal-ip` granularity is spec
  expressibility, not realized enforcement — on the measured
  build the effective outbound posture is all-deny** (fs
  enforcement unaffected). The fixture's own
  `net_connect_allow` leg (127.0.0.1) may have been
  capability-gated on the reference host too — its `10013`
  was attributed to loopback isolation but the same gate
  produces that result. SDK capability selection
  (`network_policy_helpers.rs`): `internetClient` iff egress
  has allows or default=allow; `privateNetworkClientServer`
  iff `ingress.default=allow`; `networkLoopback` iff
  `host_loopback=allow`; when an egress/ingress policy exists
  the policy *owns* those capability names (user-supplied
  values are stripped and re-added per policy). The upgrade
  delta is now fully scoped: emit the capability string the
  policy implies + the v1.1 endpoint fields + relax the
  `psec_ipv4_expressible`/port refusals.
- **Full v1.1 surface verified end-to-end through a
  warden-format spec** (extended `winiso-v11` probe,
  `psec-spec-test-v11surface-9711.json` +
  `psec-run-*-9711.json`): at `CreateProcessSecurityEnvironment`
  the ladder accepts `allowed_appcontainer_peer` (string),
  `ui_restrictions` (u64), `disallow_win32k` (u8),
  multi-capability strings, `fs_enumerate`, `except` subnets
  in a `DestinationRule`, and `EndpointPolicy.deny` rules —
  all hr=0. At runtime, through warden-emitted bytes: **deny
  > allow** (10.20.30.0/24 allow + 10.20.30.40/32 deny →
  .40 `10013`, .41 `timeout`), **`except` pokes holes**
  (same spec minus deny-rule, .40 `10013`, .41 `timeout`),
  and **loopback stays denied even with `internetClient` +
  an explicit `127.0.0.1/32` allow** — the host-local
  exemption gate sits *above* both the capability gate and
  the egress rules, consistent with `hostLoopback` being a
  separate mechanism.
- **Loopback resolved into two independent switches — the
  capability opens outbound, the `host_loopback` bit gates
  inbound (all measured on this build)**: with
  `capabilities:"internetClient,networkLoopback"` a
  container's connect to `127.0.0.1:<parent-listener>`
  **succeeded end-to-end** (`net_connect_allow` → `ok
  connected`; and to a non-listening port `10061`
  RST-instead-of-`10013`), **with no egress rule covering
  127.0.0.1 at all** — `networkLoopback` is an all-loopback
  class switch that bypasses the egress rules, not a
  rule-scoped grant (`psec-lbcap*.json`). `host_loopback`
  does NOT drive outbound: `ingress{default:0,host_lb:1}` +
  `internetClient` (no `networkLoopback`) still denied
  loopback connect `10013` (`psec-lbbit.json`). Inbound
  measured via a `listen`-mode child + parent probes: with
  `ingress{default:0,host_loopback:1}` the child accepted
  **both** `127.0.0.1` and the host's own LAN address —
  same-host traffic is internally loopback-class; with
  `host_loopback:0` both probes were silently dropped
  (timeout) regardless of `networkLoopback` /
  `privateNetworkClientServer` caps — **the bit is
  necessary and sufficient for same-host inbound; neither
  capability participates** (`psec-ing1..5.json`,
  `psec-ladder-r13.json`). `privateNetworkClientServer`
  presumably governs remote-source inbound — untestable on
  a single host. Design consequence for the rendezvous
  path: container→host needs the `networkLoopback` cap;
  host→container needs `host_loopback:1`; the declared-peer
  path (`allowed_appcontainer_peer`) remains the
  identity-scoped alternative.
- **`fs_enumerate` precedence + proxy exhaustion (measured)**:
  a directory listed in BOTH `fs_deny` and `fs_enumerate`
  denies `read_dir` outright (`err:5`) — deny wins over
  enumerate exactly as it wins over read/write
  (`psec-enumdeny2.json`). The `NetworkPolicy.proxy` form was
  exhausted further: five URL shapes (bare `ip:port`,
  `https://`, `localhost`, `socks5://`, `[::1]`), every
  spec-composition variant, spec `Ver(1,2)`/`Ver(2,0)`
  headers (`0x80070032` — versions above 1.1 unsupported,
  consistent with `minor=1` max), and create-flags 1–7 —
  **all `0x80070057`** (`psec-ladder-r13.json`). **Resolved
  by the r17 ladder**: every one of those forms lacked the
  required combination — `proxy` is accepted only with an
  `allowed_appcontainer_peer` co-present, **no** `egress`
  node, and the `privateNetworkClientServer` capability
  (see the `NetworkPolicy.proxy` entry). No outside-API or
  runtime-registered endpoint is needed; the field is a
  normal `CreateProcessSecurityEnvironment` input.
- **Host-local class is fully outside the rule system in
  BOTH directions — and `ingress.default` does not cover it
  (measured)**: `ingress{default:1,host_loopback:0}` still
  dropped both same-host probes silently — `default` covers
  only the remote-source class; `host_loopback` is the
  *sole* same-host inbound switch (`psec-ing6.json`). The
  complete picture: egress rules + capabilities govern
  non-local traffic; `networkLoopback` cap governs outbound
  host-local (transport-agnostic — UDP to `127.0.0.1` was
  **delivered** under the cap while the same send without it
  was silently dropped, `psec-udp*.json`); `host_loopback`
  bit governs inbound host-local. Neither rule nor
  `default_action` reaches the host-local class at all.
- **Environment delivery under PSEC is fully characterised —
  and it is a contract constraint**: parent process env is
  **scrubbed** (WINISO_* set in the caller unseen in child,
  `psec-env.json`) and an explicit `lpEnvironment` block
  fails `CreateProcessW` with `ERROR_ENVVAR_NOT_FOUND`
  (203) — matching the product's documented contract
  (`src/warden/windows_proc.rs` L151-158 refuses env on the
  PSEC path). The child runs on a mechanism-managed
  environment (OS injects `Packages\sandbox.{id}` + TEMP/TMP
  per SDK evidence). Consequence: `command.env` cannot be
  delivered at spawn on the PSEC path — a launcher/shim
  that applies env via argv (or an env-applying bootstrap)
  is the only route.
- **UDP egress under warden-format spec is unmediated —
  consistent with the MXC measurement**: `send_to()` to a
  non-local destination under deny-all + `internetClient`
  returns `sent:14` with no error — no 10013 equivalent for
  UDP (`psec-udp2.json`). Host-local UDP silently dropped
  without `networkLoopback`, delivered with it (`psec-udp*`)
  — the class gates do cover UDP; only the rule layer does
  not.
- **`allowed_appcontainer_peer` is inert without the proxy
  field — and AppContainer listeners cannot serve inbound
  at all without exemption (measured negative)**: a
  named-profile AppContainer child (`--profile-name
  mcp-writ-peertest`, `--net` incl. the server capability
  SIDs) bound `127.0.0.1` but accepted nothing — **even a
  plain host-process connect timed out** (`acrun-listen*`).
  AC loopback inbound needs an exemption, and a PSEC spec's
  `peer` field alone does not create one — the PSEC child
  with `peer` declared + `networkLoopback` reached
  `timeout` on the connect (policy passed, but the
  peer-side endpoint could not serve). **The exemption is
  created by the `proxy`+`peer` combination**: the r17
  ladder shows the spec is accepted only with both present,
  and the r17 live leg then reached the declared-identity
  listener on the declared endpoint unprivileged
  (`ACCEPTED` server-side) — the in-spec pair is the
  nonprivileged wiring the shim previously appeared to be
  (LoopbackExempt is the *fallback-tier* equivalent, not a
  requirement of the spec path).
- **The mechanism-managed environment's actual contents
  (measured)**: 41 vars — a full standard user-profile
  environment with **TEMP/TMP/LOCALAPPDATA rewritten to
  `Packages\sandbox.{guid}\AC`** while USERPROFILE, APPDATA,
  Path, SystemRoot, COMPUTERNAME, USERDOMAIN stay pointed at
  the real profile. Custom (non-standard) vars are absent —
  the block is regenerated, not filtered (`psec-base15.json`
  `env_dump`).
- **`disallow_win32k` is process-init-fatal for a
  console-subsystem binary on this build — a blunt switch**:
  a `sleep` child dies in ~133ms before `main` (baseline
  3s), and every attempts variant (full, lite, isolated
  win32k legs) produces no output at all — nothing in the
  battery gets far enough to emit. This is *stricter* than
  the SDK's `ui.disable` posture where tier-1 children run
  and only user32-linked exes fail `0xC0000142` — the
  spec-level field kills console init outright
  (`psec-wk-*.json`). Upgrade consequence: do not emit
  `disallow_win32k` on the warden path until the surviving
  process class is characterised (GUI-subsystem or
  already-headless binaries may differ).
- **`ui_restrictions` has a co-dependency the schema hides —
  it requires `disallow_win32k` (measured)**: `ui` alone in
  a full spec → `0x8007000d` for every mask (`0x1f`…`0xff`,
  `0xffff_ffff_ffff_ffff`); add `disallow_win32k` and every
  mask including `0x0`/`0xff` is accepted (`psec-ui-*.json`)
  — the validator rejects the combination, not the mask
  value. Note the earlier ladder's `ui-restrictions`
  variant was accepted because the spec contained *only*
  version+ui — combination rules differ when fields stand
  alone.
- **Egress semantics fully confirmed through warden-format
  spec**: port **ranges** enforced (`/24:61200-61299` →
  in-range `timeout`, out-of-range `10013`); **protocol
  scoping** enforced (a `protocol=udp` rule does NOT cover a
  TCP connect → `10013`); **IPv6 destination rules**
  enforced (`fe80::/10` allow → `timeout`, unruled `fe80::`
  → `10013`; unrouted prefixes return `10051` before policy
  — routing failures mask policy so only routable prefixes
  are measurable); `::1` sits inside the `networkLoopback`
  class (`10061` under the cap) while `fe80::` is
  rule-gated like non-local v4 (`psec-prt/proto/v6*.json`).
- **fs on the warden spec: subpath-deny + normalization
  resistance (measured)**: `--rw dir --deny dir\sub` denies
  read+write into `sub` while sibling writes stay `ok` —
  deny carves inside grants, matching the MXC tier
  behaviour. `\\?\`-prefixed and forward-slash spellings of
  a denied dir are both `err:5` — the deny is
  normalization-proof on the tested forms
  (`psec-subdeny/norm*.json`).
- **`fs_enumerate` (v1.1-only) is a genuinely new capability
  axis — list-only filesystem access**: with
  `fs_enumerate=[dir]` and no read grant, the child's
  `read_dir` returns `ok 1 entries` while reading the file
  inside is `err:5` (`psec-run-fsenumerate-9711.json`). No
  matrix row has an enumerate-vs-read distinction — it maps
  to a possible new `os.fs.enumerate` granularity. **Version
  gate nuance**: `fs_enumerate` under `Ver(1,0)` →
  `0x80070032`, accepted under `Ver(1,1)` — the version
  header gates *new-surface* fields (enumerate, presumably
  ingress) while not gating fields present since v1.0 (net
  endpoints accepted and enforced under either header).
- **`NetworkPolicy.proxy` spec form — ACCEPTED; three
  measured prerequisites identified (r17 ladder — minimum
  known requirement, not a proven-complete rule)**: the
  field is consumed by `CreateProcessSecurityEnvironment`
  when all three hold simultaneously:
  (a) `allowed_appcontainer_peer` is present (any name —
  registered `mxc.probe.proxy`, fake `MyPeer-Profile`, and
  reserved `MXC-Loopback` all accepted; *absent* →
  `0x80070057`);
  (b) **no `egress` node** — proxy and direct egress are
  mutually exclusive policy forms (peer+proxy+egress →
  `0x80070057`, matching the SDK's "mutually exclusive"
  comment);
  (c) `privateNetworkClientServer` capability — absent or
  `internetClient` → `0x80070057` (the DLL's own validation
  strings: *"internetClient / internetClientServer are not
  supported with a proxy; use privateNetworkClientServer"*).
  `pvtNCS`+`networkLoopback` also accepted; version header
  1.0 and 1.1 both work. Every earlier rejection (22+
  forms) lacked at least one of (a)–(c) — none carried a
  peer *without* an egress node. **Declared-but-untested
  constraints**: the DLL's validation strings additionally
  require a *loopback* proxy URL (*"Proxy URL must be
  loopback (127.0.0.1 or ::1)"*) — every accepted form used
  a loopback URL, so non-loopback URLs were never tested;
  `internetClientServer` is prohibited by the same strings
  but only `internetClient` was measured-rejected. End-to-end enforcement was
  then re-demonstrated **unprivileged on T1** this session:
  `127.0.0.1:61243` under profile `mxc.probe.proxy` →
  `ok connected` (listener `ACCEPTED`), same identity port
  61244 → `10013`, `127.0.0.1:1` → `10013`
  (`r17-proxy-accept.json`, `r17-peer-live.txt`,
  `r17-peer-listener.txt`).
- **Capability semantics resolved — `internetClient` is a gate,
  `networkLoopback` is a bypass; `default_action=allow` still
  needs the gate (measured)**: three spec variants through
  warden bytes distinguish the models. `egress{default:deny,
  no rules}` + `internetClient` → all destinations `10013`
  (`r15-cap-gate-denyall.json`) — the cap enables *rule
  evaluation*, it does not itself grant egress (unlike
  `networkLoopback`, which bypasses rules entirely).
  `egress{default:allow}` with **no** capabilities → all
  destinations `10013` (`r15-defaultallow-nocaps.json`) — the
  capability gate sits **in front of even an open policy**;
  add `internetClient` to the same spec → every destination
  `timeout` (`r15-defaultallow-caps.json`). And
  `capabilities:"privateNetworkClientServer"` alone + an
  `allow 10.20.30.0/24` rule → the allowed destination is
  still `10013` (`r15-cap-pvtncs.json`) — **private-address
  egress is gated by `internetClient`, not by the private
  cap**; the classic AC public/private class split does not
  apply to spec-driven egress. Net: on the egress-rule path
  warden must emit `internetClient` whenever egress is
  allowed at all (rules or default), `networkLoopback` only
  when container→host traffic is intended, and
  `privateNetworkClientServer` contributes nothing on the
  outbound path. The `proxy` policy form is a different
  shape — no `egress` node and `privateNetworkClientServer`
  required instead (the `NetworkPolicy.proxy` entry).
- **fs grant precedence is a strict total order, not a union
  (measured)**: probing the same directory in two lists —
  `rw∩deny` → every access `err:5`; `ro∩rw` → read `ok`,
  write `err:5`; `enumerate∩rw` → list `ok`, write `err:5`;
  `enumerate∩ro` → list `ok`, **read `err:5`**
  (`r15-fs-*.json`). The first matching class in
  **deny > enumerate > read_only > read_write** wins outright
  — a path in `fs_enumerate` is list-only *even when also in
  `fs_read_only`*, and a path in `read_only` loses write
  *even when also in `read_write`*. Design consequence:
  grant lists must be kept disjoint per path — overlap
  silently applies the *more* restrictive class.
- **The security environment propagates to plain
  `CreateProcess` descendants (measured)**: a grandchild
  spawned by the PSEC child (unmodified `Command::spawn`, no
  attributes) running `fs-probe` reported
  `ro_read:ok, rw_write:ok, deny_write:err:5, deny_enum:err:5`
  (`r15-gc-probe.json`) — the same policy binds the whole
  process tree, no descendant escape exists. The earlier
  `spawn_grandchild err:5` observations were a filesystem
  artifact (the exe path was outside the grants); with the
  exe copied inside an `rw` grant the spawn succeeds and the
  job object's kill-on-close reaps it (`gc_killed:true`).
- **`network_policy` absence fails closed — and capabilities
  alone cannot open egress (measured)**: a spec with no
  network-policy field at all denies every destination
  `10013` — adding `internetClient` changes nothing
  (`r16-netnone*.json`). The capability gate sits in front
  of *rule evaluation*; with no policy there is nothing to
  evaluate and the default is deny. Safe by construction:
  an emitter that omits the field cannot accidentally open
  the network.
- **Unknown capability strings are accepted but inert
  (measured)**: `capabilities:"bogusCapabilityName"` creates
  the environment (`hr=0`, child runs) yet gates nothing —
  allow-rule destinations still `10013`
  (`r16-boguscap.json`). A typo'd capability name fails
  closed, not open — but also fails *silently*; a warden
  validator should whitelist the known names itself rather
  than trust the spec parser to complain.
- **File-level `fs_deny` works inside an `rw` grant
  (measured)**: `secret.txt` listed in `fs_deny` denies
  read+write (`err:5`) while sibling files in the granted
  directory stay writable (`r16-filedeny.json`) — grants
  are path-exact, not directory-only, on the deny side too.
- **UDP same-host inbound follows the TCP model
  (measured)**: `ingress{default:0,host_loopback:1}` — the
  container's bound UDP socket received datagrams from BOTH
  `127.0.0.1` and the host LAN address; `host_loopback:0`
  (even with `networkLoopback` cap) delivered nothing
  (`r16-udp-in-*.json`). The inbound switch is
  transport-agnostic. This refines the earlier "UDP hole is
  egress-only" note: UDP *inbound* is properly gated — the
  unmediated part is outbound `send_to` only.
- **DNS stays dead under deny posture — `networkLoopback`
  does not revive it (measured)**: `ToSocketAddrs` inside
  the child returns `err:11001` for a real hostname under
  deny-all egress, and still fails when the loopback
  capability is added (`r16-dns-*.json`). The MXC backend's
  dnscache-mediated resolution does not carry over to the
  raw spec path — name resolution on the warden path needs
  a resolver the rules actually permit (or the proxy).
- **processmodel.dll export surface maps the real feature
  set (new)**: the DLL exports `Experimental_QuerySandboxSupport`
  (callable, returns `0x1` under a `(void)->u64` reading),
  `Experimental_CompileSandboxSpecificationInternal` +
  `Experimental_FreeSandboxSpecification` +
  `Experimental_CreateProcessInSandbox`/`...AsUser...`
  (a *compiled-spec* API family distinct from
  `CreateProcessSecurityEnvironment`), the `Sbe*` sandbox
  backend twins (`SbeCreateProcessSecurityEnvironment`,
  `SbeDetachProcessSecurityEnvironment`,
  `SbeGetSecurityEnvironmentAppContainerSid`), and
  `NetworkIsolationCreate/DeleteAppContainerLoopbackRules`
  + `WinHttpConnectionSet/DeleteProxyInfo`. Embedded
  validation strings state the in-spec proxy contract
  verbatim: *"internetClient / internetClientServer are
  not supported with a proxy; use
  privateNetworkClientServer"* and *"privateNetworkClientServer
  is required with a proxy for loopback access"*, *"Proxy
  URL must be loopback (127.0.0.1 or ::1)"* — yet all four
  `privateNetworkClientServer`-bearing variants (with and
  without egress/hostlb/peer) still return `0x80070057`
  (`r16-ladder.json`) — superseded by the r17 ladder: the
  earlier forms were rejected not because the field is
  unhandled but because none satisfied the full acceptance
  rule (peer required + egress node absent + pvtNCS cap —
  see the `NetworkPolicy.proxy` entry above). With that
  combination `CreateProcessSecurityEnvironment` accepts
  the spec and enforces it unprivileged (r17 live leg).
  The two SDK surfaces by dispatch: **T1 emits the proxy
  field in-spec** (`build_psec_v1_network_policy` —
  `network_proxy.is_enabled()` → `network.proxy{url}`,
  egress omitted) and the OS consumes it — this is the
  measured nonprivileged route. **T2/T3 / the
  AppContainer-runner fallback** (selected for legacy
  `networkProxy` requests without `runtimeConfig`, or when
  the BaseContainer spec is unusable) instead runs
  `ProxyCoordinator`: an elevated `winhttp-proxy-shim`
  calling `WinHttpConnectionSetProxyInfo` + LoopbackExempt
  (proxy_coordinator.rs). The `Sbe*`/`Experimental_*`
  compiled-spec family exists but is not the field's
  consumer — blind-signature probes reach arg-validation
  only (`exp-compile`/`sbe-create` → `0x80004003`/
  `0x80070057`; deeper signature recovery out of probe
  scope — `r16-api-*.txt`).
- **macOS remaining gap**: `connect-proxy` is already the
  maximal adopted route (fqdn TCP); the only kernel-level
  per-flow alternative is `NEFilterDataProvider`/`NEAppRule`
  (Network Extension content filter — entitlement-heavy,
  app-bundle model, not a sandbox mechanism); the ES
  descendants client has no IP-network event (declined
  stands). Nothing further to close there.
- **Linux `deny_all_others` UDP/DNS gap — a v10 option**:
  seccomp currently kills UDP at socket creation (DNS dead).
  Landlock v10's `BIND_UDP`/`CONNECT_SEND_UDP` is
  port-scoped (never address-scoped) — it could allow
  `udp:53` while denying the rest (resolver DNS restored,
  DNS-tunnel exfil risk accepted) instead of killing all
  UDP. Still gated on ≥7.2 kernels + an unreleased crate.
- **DNS unaffected in both modes**: `ToSocketAddrs` inside the
  container resolved `example.com` (v4+v6), `localhost`, and returned
  NXDOMAIN for `.invalid` under both direct deny-all and proxy mode —
  resolution rides the host `dnscache` service, not a raw egress flow
  (`dns-deny-direct.txt`, `dns-proxy-mode.txt`). Relevant upside:
  name-scoped policy could mint IP grants at resolve time, as the
  native Landlock path already does.
- **proxy mode (`runtimeConfig.networkProxy`) measured**: requires
  `ingress.default=Allow` and is mutually exclusive with egress rule
  lists. With a local HTTP proxy at `127.0.0.1:59199`, every **raw**
  socket connect inside the container — loopback non-proxy port and
  `203.0.113.1:443` alike — returned `WSAEACCES 10013`; only the proxy
  endpoint is reachable (fail-closed). A `curl` child reached
  `http://neverssl.com/` through the proxy (`CURL_STATUS=200`; the
  proxy logged `GET http://neverssl.com/ HTTP/1.1`). Conclusion:
  destination scoping in proxy mode moves to the proxy layer, which can
  apply per-destination policy *including* loopback targets — the
  loopback anomaly above does not apply to the proxy route. The SDK
  also injects `HTTP_PROXY`/`HTTPS_PROXY` into the child's env; whether
  a workload honors them is a workload property (raw-socket
  non-conformance stays fail-closed, which is the property warden
  needs).
- stdio/lifecycle: `spawn()` gives live `stdin/stdout/stderr`
  `Box<dyn Read/Write>` pipes, `id()`, `kill()`, `wait()` — sufficient
  for the MCP stdio contract. `take_native_stdio()` must be called
  before individual `take_*` streams (ordering quirk). The raw
  one-shot `__ffi::spawn_container_json` likewise returns a
  Child-like handle — `take_stdout`/`take_stderr`/`try_wait` all
  functional (`stderr` carries cmd's `アクセスが拒否されました`
  diagnostics; `exit=Some(0)` retrieved — earlier `exit=None`
  reports were a driver artifact of not draining stderr/waiting).
- registry/objects/tree: HKLM+HKCU writes `err:5`; `Local\` mutex ok.
- **named objects are namespaced (measured)**: a container child could
  not `OpenMutex`/`OpenEvent`/`OpenFileMapping` host objects under
  `Local\` *or* `Global\` — all `err:2` (name not found), while its own
  `CreateMutex` succeeded (`named-objects.txt`). The object-namespace
  boundary is real.
- **process/token surface (measured)**: `EnumProcesses` sees only the
  container's own 3 processes — the process namespace is private and
  `OpenProcess(QUERY_INFORMATION)` on them yields only the tree's own
  handles; the token carries **2 privileges** (minimal, no
  `SeDebug`/`SeImpersonate`); HKCU resolves to the container's own
  hive (`\REGISTRY\USER\S-1-12-1-*` — readable, writes `err:5`), not
  the user's (`ipc-surface.txt`). **HKLM and `HKU\.DEFAULT` reads are
  denied by default** — `reg query` produced no values on either
  (`leg-hklm.txt`).
- **grandchildren inherit the container (measured)**: a `cmd /c`
  intermediate spawned `winiso attempts` — the grandchild ran as
  `is_appcontainer=true` IL 4096 with a *fresh* per-process AC SID, and
  every policy check still held: denied-path fs ops `err:5`, HKLM write
  `err:5`, denied TCP destination `10013`, loopback connect to a bound
  host port refused `10061` (`grandchild-inherit.txt`). The security
  environment travels with the process tree, not the spawning process.
  After `run()` completed no grandchild process remained.
- **Cross-container isolation is complete (measured with two
  simultaneous containers, `xcont.txt`)**: sibling A created a
  `Local\` mutex + named pipe + a file in its package dir + a
  `127.0.0.1` TCP listener; sibling B could see none of them —
  mutex/pipe `err:2`, `OpenProcess(A pid)` `err:5`, A's package
  file `err:5`, `EnumProcesses` returns only B's own 3 pids, and
  each container received a **unique** `sandbox.{guid}` package
  directory (`LOCALAPPDATA` differs). Cross-container loopback TCP
  was denied too (`10013`) — though under the default-deny
  posture every loopback connect is denied anyway (see network
  default above); the per-AppContainer-identity socket scoping
  observed with `allowedProxyPeer` is the same mechanism that
  keeps containers from sharing each other's loopback services.
  Implication for warden: parallel MCP children cannot
  communicate or collide — no shared object namespace, files,
  processes, or sockets.

- Symptom (first probe round): a child image that **imports
  `ole32.dll` exits `0xC0000142` (`STATUS_DLL_INIT_FAILED`) before
  `main`**, and `node.exe` (ole32 import) failed the same way —
  reported earlier as a blocking defect.
- Root cause (this round): `UiPolicy.disable` defaults to `true`,
  which maps to **DisallowWin32kSystemCalls** — the container's win32k
  surface is disabled. `user32.dll`/`gdi32.dll` then fail to
  initialize in the child, and `ole32.dll` (depends on user32) fails
  behind them. Measured: `LoadLibraryW` inside the container →
  `user32 err=1114`, `ole32 err=1359`, `gdi32 err=8`
  (`ui-default-user32-fail.txt`).
- With `ui.disable=false` (clipboard stays `ClipboardPolicy::None`,
  `allow_input_injection` stays `false`): `user32`/`ole32`/`gdi32` all
  load (`ui-open-loadlib.txt`) and **`node.exe` v24.11.1 runs to
  completion → `NODE_MXC_OK`** (`node-ok-ui-open.txt`). `python.exe`
  also runs (install dir granted `ro` → `PY_MXC_OK`, earlier round).
- Conclusion: **not an OS-level incompatibility** — a policy knob. The
  trade is real, though: `ui.disable=false` re-enables win32k
  (windows/GDI syscalls inside the session) while clipboard and input
  injection remain denied by default. Tier-2/3 behavior stays
  **unverified** (elevated host-prep out of scope).

### Lifecycle / resource / audit measurements (this round)

- Startup: `v1::run` of `cmd /c exit 0` → **80/84/85 ms** end-to-end
  (3 samples, `startup-timing.txt`); battery legs ~77–325 ms.
- Timeout: `timeout_ms=2500` against `sleep 30000` → `TimedOut` at
  **2573 ms** — enforced (`timeout-kill.txt`).
- `CaptureDenials` (block mode): `metadata.capture_denials` =
  `kind:"captureDenials"`, `output_path`, `exit_code:0`,
  `total_denials:5`, `denied_resources_truncated:false`; JSON records
  `resource`/`resourceType`/`accessType`/`pid`/`filetime` per denial —
  registry read, `ui` (`ConvertToGui`), file read/write
  (`capture-denials.txt`, `denials.41596_*.json`).
- `take_native_stdio()` must precede `take_stdin/stdout/stderr`
  (ordering error otherwise — recorded earlier).

### UI surface under `ui.disable=false` — measured residual exposure

With `ui.disable=false` and the rest of `UiPolicy`/`ProcessContainerUi`
at defaults (`clipboard:None`, `allow_input_injection:false`,
`isolation:Container`, `system_settings:None`, `ime:false`), a child
binary probing win32k directly (`ui-surface-open.txt`):

- `OpenClipboard` (read **and** write attempts) → `FAIL err=5` —
  clipboard stays blocked.
- `SystemParametersInfoW` write → `err=5` — system-settings blocked.
- `CreateWindowExW`/`RegisterClassW` → **window creation succeeds**
  (expected with win32k enabled — on the container's own desktop).
- **`SendInput` with a well-formed keyboard event returned `sent=1` —
  the injection was *accepted*** despite `allow_input_injection=false`.
  Scope resolved by a dedicated desktop probe (`desktop-scope.txt`):
  `OpenWindowStation("WinSta0")` → `err=5`, `EnumWindows` sees **0**
  windows, `GetForegroundWindow` is outside the visible set, and
  `OpenInputDesktop` resolves to the container's **own** `Default`
  desktop. Injection therefore lands inside the container's private
  desktop only — it cannot reach the interactive session. (What it
  *can* do is inject input into the container's own UI surface —
  self-referential, not a host threat.)

`ProcessContainerUi` (ProcessContainerConfig.ui) exposes finer knobs:
`isolation ∈ {Desktop, Handles, Atoms, Container}`, `ime`,
`desktop_system_control`, `system_settings`. The knob has real teeth
— measured: `isolation="desktop"` put the container **on the user's
desktop** (`EnumWindows` returned 283 windows incl. the live
foreground title; `WinSta0` still `err=5` but the window/input
surface is shared — `SendInput` there would reach the interactive
session). Default `container` gives the private desktop measured
above; `desktop` must never be selected for untrusted children
(`ui-iso-desktop.txt`). The intermediate levels measured as an
exposure gradient (`leg-ui-handles.txt`, `leg-ui-atoms.txt`):
`handles` still confines `EnumWindows` (0) but the *input desktop
becomes reachable*; `atoms` is **as exposed as `desktop`** (284
windows + live foreground title). Only `container` gives a private
surface. Two more knob caveats measured: generic `ui.clipboard:"read"`
did **not** open clipboard reads on T1 (`open` still `err:5`), and
`processContainer.ui.systemSettings:"parameters"` did **not** permit
`SystemParametersInfo` writes (`err:5` — `leg-clip.txt`,
`leg-sysp.txt`) — several UiPolicy/ProcessContainerUi knobs are
no-ops or need pairing at this tier; verify each mapping at
adoption. Host capabilities
`canBlockClipboardRead`/`canBlockInputInjection`/
`canBlockInputMethodChanges` are advertised — but the generic
`UiPolicy` flag did not produce the block measured above, so the exact
mapping needs verification at adoption time.

### `CaptureDenials` — both modes measured

- `Block` (previous run): deny enforced + recorded — `total_denials:5`.
- **`Allow` (learning mode): ungranted access is *permitted* and
  recorded** — `fs_write_ro` → `ok written`, `reg_write_hkcu` →
  `ok created+deleted`, `total_denials:11`; explicitly *denied* paths
  stayed denied (`fs_*_deny` → `err:5`)
  (`capture-allow-mode.txt`, `denials.120164_*.json`). Usable for
  policy-development runs: enumerate what a workload would need.
- **Gap: network denials are not recorded (measured).** A capture run
  whose child hit two denied TCP destinations (`10013` each) produced
  only `file`/`registry`/`ui`/`capability` records — zero `network`
  entries (`denials.133628_*.json`). Egress denials have no audit
  trail at this level; proxy-mode mediation would restore
  observability at the proxy layer.
- JSON per denial: `resource`/`resourceType`/`accessType`/`pid`/
  `filetime` + run summary (`exit_code`, `total_denials`, truncation
  flag); `retain_etl` option exists for ETL sealing.

### Combined real-config leg + `spawn` under proxy

- `ui.disable=false` + `networkProxy` + fs policy + env map +
  `node.exe` → `NODE_OK`; **`HTTP_PROXY`/`HTTPS_PROXY` were present in
  the child's environment** pointing at the configured proxy
  (`combined-node-proxy.txt`) — the full warden-shaped policy composes.
- `spawn()` under proxy mode → live stdio + `SPAWN_PROXY_OK`
  (`spawn-proxy.txt`) — the MCP stdio contract holds in proxy mode.

### Wire surface, tier dispatch + fs-enforcement internals (source-verified)

- **`containment:"appcontainer"` is an ALIAS of `processcontainer`**
  (wire `parse_wire_name` maps both to `Self::ProcessContainer`) —
  the earlier "legacy backend parity" legs therefore re-ran the same
  T1 dispatch, not the downlevel `AppContainerScriptRunner`. So the
  fs/egress/UDP observations from those legs are **T1 measurements
  only** — they say nothing about whether the downlevel runner or
  the T2/T3 tiers behave equivalently. Whether any AppContainer-tier
  mechanism mediates UDP is **unverified**: **T2/T3 were never
  exercised** — the fallback detector always selects T1 here (PSEC
  usable) and there is no runtime tier-forcing switch
  (`MXC_FORCE_*` envs are `#[cfg(test)]` only).
- `containment:"process"` resolves to `ProcessContainer` on Windows
  ("OS-native process sandbox, resolved per host" — Bubblewrap on
  Linux, Seatbelt on macOS).
- One-shot wire `containment` accepts: `process`, `processcontainer`,
  `appcontainer`, `lxc`, `bubblewrap`, `seatbelt`, `macos_sandbox`,
  `isolation_session`, `wslc` (feature-gated — "not compiled" on this
  build). `microvm`/`vm`/`windows_sandbox` are **not valid one-shot
  variants** — VM-class, lifecycle API only. `WindowsSandbox.exe` is
  present on this host (feature likely enabled — admin needed to
  confirm via DISM).
- **fs enforcement internals — DACL mutation is a fallback-tier
  mechanism only**: the dispatcher keeps `deniedPaths` native on T1
  (PSEC — **no host DACL changes**). T2 stamps deny ACEs for the
  child's AppContainer SID on `denied_paths` (BFS cannot express
  deny-inside-grant); T3 stamps ACEs for all policy paths. ACEs are
  reverted on `DaclManager` drop with a crash-safety state file.
  `fallback.allowDaclMutation` (default true) consents to this.
  Caveat noted in-source: concurrent runs with the same
  `container_id` share the derived AC SID — the second run's cleanup
  `REVOKE`s the first's grants; parallel runs need distinct ids.
- **Proxy mediation is two different mechanisms by tier**: T1 writes
  `network.proxy` + `allowed_appcontainer_peer` into the PSEC spec
  when `runtimeConfig.networkProxy` is set — the host consumes and
  enforces it **unprivileged** (r17: measured prerequisites —
  peer-required / egress-absent / `privateNetworkClientServer`
  cap; live leg
  `127.0.0.1:61243` `ok connected` + listener `ACCEPTED`, other
  endpoints `10013` — no shim, no elevation). T2/T3 and the
  AppContainer-runner fallback (legacy `networkProxy` requests
  without `runtimeConfig`, or when the BaseContainer spec is
  unusable) instead launch `winhttp-proxy-shim.exe` **elevated via
  UAC** (`ShellExecuteEx runas`) and call
  `NetworkIsolationSetAppContainerConfig` (LoopbackExempt) to set a
  per-AppContainer WinHTTP proxy — **admin at every spawn and only
  WinHTTP clients get proxied**. `MXC-Loopback` is the peer name the
  SDK writes as `allowed_appcontainer_peer` whenever
  `host_loopback=allow` is in effect; with `hostLoopback=deny` the
  caller's `allowedProxyPeer` is used instead
  (`base_container_helpers.rs`). **Consequence: unprivileged proxy
  mediation exists only on T1 (verified); the fallback tier is
  admin-gated.**
- `least_privilege_mode` (ContainerPolicy flag) adds
  `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` — the LPAC
  bit, i.e. the same hardening the shipping warden path already uses.
- **Job object**: `JOB_OBJECT_UILIMIT_*` restrictions (the UiPolicy
  enforcement layer) + `KILL_ON_JOB_CLOSE` — **no memory/CPU limits**
  (source-verified; resource caps don't exist on this surface).
- **Concurrency**: three parallel `spawn_container_json` runs all
  succeeded (`concurrent.txt`) — no serialization bottleneck for
  per-request containers (mind the same-`container_id` revoke caveat
  on mutation tiers — N/A on T1).

### `Containment::IsolationSession` — evaluated, **disqualified**

Exercised with the `isolation_session` crate feature. The backend
rejects requests unless they acknowledge a fully permissive shape —
measured contract violations:

- `network.egress.default=allow`, `network.ingress.default=allow`,
  `hostLoopback=allow`, **no rules, no runtimeConfig.networkProxy** —
  egress control is structurally inexpressible.
- **filesystem policy unsupported** ("filesystem policy is not
  supported by the isolation session backend").
- `process.env` without `inheritDefaultEnv=true` unsupported — child
  always inherits the agent user's default environment.
- working-directory grant semantics differ: a working dir inside the
  caller's user profile failed `RunProcessWithOptionsAsync
  0x8007065f` (agent user cannot access it); with `working_directory`
  omitted the launch succeeded.
- Measured launch: `cmd /c echo ISO_OK` → `ISO_OK`, `Exited(0)`,
  ~3.4 s wall (`isolation-session.txt`) — materially slower than
  ProcessContainer's ~80 ms.

Verdict: it isolates at the *session/user* level with no fs/net/env
policy surface — it cannot express the warden contract.

`windows_sandbox` (listed in `available_backends` with empty
capabilities here) is a lifecycle daemon + guest-binary VM-class
backend (`src/backends/windows_sandbox/lifecycle/{vm,control_plane,...}.rs`)
— microVM-plan territory, not a process-container replacement.

### Verdict — **conditional candidate (was: hold)**

ProcessContainer tier 1 now measures as a *viable* isolation engine
for the warden contract — curated-baseline fs with robust deny
enforcement, explicit env contract, live stdio, timeout kill, denial
capture, private desktop, private object+process namespaces,
grandchild inheritance — with four architecture-level conditions:

1. **UDP egress is unmediated — the biggest measured hole.** Under
   `egress.default=Deny`, UDP reaches arbitrary destinations (delivery
   confirmed by a host listener); explicit UDP deny rules do not apply;
   **proxy mode does not fail-close UDP** (only raw TCP is confined to
   the proxy endpoint). Where DNS resolution stays live (modes that
   permit host-local traffic — see condition 3; it is **not** live in
   every mode), a container has a working exfiltration channel.
   **Adoption requires an effective UDP block outside
   ProcessContainer's rule set — no tier-1 mechanism was found —
   before deny-all enforcement can be claimed.** Absent that, use is
   restricted to policies that explicitly permit unrestricted UDP;
   treating operator acceptance alone as enforcement is an unsafe
   downgrade. (Warden's native Linux route has the complementary gap:
   deny-all kills UDP entirely; neither engine does destination-scoped
   UDP natively.)
2. **Node-class workloads need `ui.disable=false`** — and the residual
   exposure is now *measured, not assumed*: clipboard and
   system-settings stay blocked (`err=5`), `SendInput` is accepted
   (`sent=1`) but lands in the container's private desktop —
   `WinSta0` opens `err=5`, `EnumWindows` sees 0 windows — so injection
   cannot reach the interactive session. Remaining task is narrower:
   verify the generic `UiPolicy` → `ProcessContainerUi` knob mapping
   documents exactly which surface each flag governs.
3. **Egress destination scoping via peer-scoped proxy — proven
   end-to-end on T1.** Direct egress enforces CIDR+port on
   **non-local** destinations (v4+v6, allow/deny/`except` all work —
   `except` exists only on allow rules); **all host-local addresses
   are exempt** — `host_loopback` is a bidirectional "host's own
   addresses" gate covering every interface IP. The validated
   architecture: **proxy +
   `processContainer.network.allowedProxyPeer` +
   `hostLoopback=deny`** — the container then reaches *only* the
   declared proxy endpoint on the declared AppContainer identity
   (same identity, different port `10013`; same endpoint via another
   host address `10013`), while raw non-proxy TCP stays fail-closed.
   Requirements this implies, all measured: (i) warden's proxy must
   run under a named AppContainer profile (`CreateAppContainerProfile`
   + `SECURITY_CAPABILITIES` spawn works unprivileged —
   `acspawn.rs` proof); (ii) `hostLoopback=deny` kills
   container-side **DNS** (`dnscache` is a host service) — name
   handling must live in the proxy (CONNECT authority), same as
   namespaced's `dnsgate`; (iii) the peer value must be a *named
   profile/PFN* (fake names accepted for spec creation; raw SID
   `E_INVALIDARG`); (iv) it
   is a `ProcessContainerConfig`/JSON-surface knob, not the generic
   `run()` policy; (v) **three measured spec prerequisites —
   not a proven-complete rule** — `proxy` requires the peer
   field co-present, no `egress` node, and the
   `privateNetworkClientServer` capability (r17 ladder;
   `internetClient`/no-caps/no-peer/egress-present all
   `0x80070057`; DLL strings also declare loopback-URL-only —
   untested, all accepted forms were loopback); (vi) **the
   unprivileged proxy path exists only on
   T1 — verified end-to-end this session** (non-elevated spec
   acceptance + listener `ACCEPTED` + `10013` on undeclared
   endpoints, `r17-*`) — on T2/T3 and the AppContainer-runner
   fallback the SDK instead UAC-elevates a
   `winhttp-proxy-shim.exe` and uses LoopbackExempt, which is
   admin-gated per spawn, so `MXC_FORCE`/fallback behavior that
   lands on T2/T3 must be treated as a hard failure for warden
   (tier pinning + PSEC support check required). The SDK injects
   `HTTP_PROXY`/`HTTPS_PROXY`; raw-socket non-conformance stays
   contained for TCP (condition 1 covers UDP).
4. **The default environment block leaks the user profile env —
   explicit `env` is mandatory.** `env:None` delivers the
   registry-backed profile block (a live API token was readable
   inside — persistent user vars flow even though process locals
   do not). Adoption must always pass a constructed `Some(vec)` —
   validation is presence-only on `SYSTEMROOT`+`LOCALAPPDATA`, so
   the clean minimum is those two + the warden-chosen set; the OS
   still rewrites `LOCALAPPDATA` to `...\Packages\sandbox.{id}`
   and injects `TEMP`/`TMP`.

Secondary deviations to price in (measured, not blocking): (a) the fs
baseline is *curated-allow read-only*, not strict default-deny —
system areas (`C:\Windows`, `Program Files`, `Public`) read ambient
with **no ambient write surface**, though profiles/secrets/other
drives stay denied and explicit `denied_paths` are
junction/`\\?\`/ADS-proof; **adoption condition**: the child
executable's directory is also ambiently readable — the launch image
ran from `%TEMP%` with no grant covering it, i.e. the mechanism
implicitly read-grants the image path. Suppressing that auto-grant is
not possible through the measured config surface (no field removes
image readability); treat it as a **filesystem contract gap**, not a
non-blocking deviation — adoption requires accepting that the child
image dir is policy-blind readable (writes remain denied; explicit
`denied_paths` elsewhere stay robust). (b) `CaptureDenials` records no `network`
denials — egress audit must come from the proxy layer; (c)
containers can `bind()` listeners — host access is gated by the same
`host_loopback` bit (bidirectional), and `ingress.default` coverage
of non-host sources is unverified; (d) `ui.isolation="desktop"`
shares the user's desktop (283 windows + SendInput reach) — must
stay `container`; (e) UDP is unmediated on the tested
AppContainer-family dispatch — the `"appcontainer"` wire name is an
alias that re-runs the same T1 dispatch, and T2/T3 could not be
forced (`MXC_FORCE_*` envs are test-only), so whether any other
tier mediates UDP is unverified; (f) several UiPolicy/`processContainer.ui` knobs are
no-ops at T1 (clipboard:"read", systemSettings:"parameters" —
isolation level is the one that demonstrably works); (g) `except`
exists only on egress `allow` rules — deny rules reject it.

Plus the standing conditions: tier-2/3 unverified (elevated
host-prep), coexistence as a separate engine selection (never a
silent substitute for the shipping AppContainer+DACL+LPAC path), and
GA-contract stability across cumulative updates.

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
- Repo pins `landlock = "0.4.7"` (`Cargo.toml`/`Cargo.lock`) — latest
  published release (2026-07-27), exposes ≤ **ABI 9**. Upstream
  **rust-landlock#140 (ABI v10) was merged to `main` on 2026-10-21** —
  `AccessNet::BindUdp` + `AccessNet::ConnectSendUdp`, `ABI::V10` in the
  compat model, `NetPort` reused for UDP rules — but **no published
  release contains it yet** → even on a 7.2+ kernel the UDP rights are
  inexpressible through the current dependency.
- Kernel availability (kernel.org, 2026-11-07): stable **7.3.3**
  (11-06), 7.2.x EOL'd at 7.2.15 (11-01), mainline 7.4-rc1; the
  current *longterm* line is **6.18.x** → caps at **ABI 7**, so v10+
  kernels exist only on the short-lived stable line for now.

### Documentation (landlock.io/kernel docs ABI table)

| ABI | kernel | delta relevant to warden |
|---|---|---|
| v8 | 7.0 | `restrict_self` `TSYNC` — process-wide enforcement; irrelevant to our child launch |
| v9 | 7.1 | named unix-domain connect control — already consumed (`ResolveUnix`) |
| v10 | 7.2 | **UDP port control** `BIND_UDP` + `CONNECT_SEND_UDP` (bind/connect/send, port-scoped — **never address-scoped**) + audit quiet flag |
| v11 | 7.3 | tracepoints; `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` — we already `prctl` |

What v10 would buy: under `deny_all_others`, UDP is currently killed
at the seccomp socket *type* pin (datagram creation denied outright)
and *any* UDP allow is dead policy for native (`select.rs` refuses /
`dead_udp_allows_without_selection` flags it). Kernel/uapi semantics
(docs.kernel.org + netdev v5 patch): `CONNECT_SEND_UDP` mediates
`connect()` **and** explicit-destination sends — "a `sendto(2)` on a
non-connected datagram socket is treated as if it were doing an
implicit `connect(2)` and will be blocked if the remote end does not
stem from a permitted rule" — exactly the unconnected-datagram hole
the unotify path cannot see today. A connected socket's later sends
are not re-checked; control happens at socket-configuration time, not
in hot paths. v10 could express **host-agnostic** UDP port grants —
but warden policies are destination-scoped (`host`+`proto`+`port`),
and Landlock has no address concept at any ABI. So destination-scoped
UDP still needs the namespaced route; v10 only helps policies that
allow a UDP port for *any* host — a marginal posture gain, plus the
kernel/upstream note that remote connect/send on an unbound socket
implicitly binds an ephemeral port, so a ruleset handling
`ConnectSendUdp` must also grant `BindUdp` on port 0 (or require a
pre-bound socket).

Cross-check vs the MXC finding (source-verified): the two engines
fail UDP in *opposite* directions. Linux native deny-all kills UDP at
socket creation — including DNS (glibc resolver dead; only
`/etc/hosts` entries resolve). The namespaced route is the only
destination-scoped UDP answer *and* the only DNS answer: its
`dnsgate::QueryCore` intercepts `:53` flows inside the child netns and
mints allowlist grants per answer (`namespaced/stack.rs`,
`namespaced/launch.rs`), refusing name-bound rules when no resolver
exists. MXC is the mirror image: DNS resolves via the host
`dnscache` service, but only in modes that permit host-local
traffic — `hostLoopback=deny` and the no-`network` default kill it
(`11001`), and on the warden spec path it stays dead even with
`networkLoopback` — while UDP egress is unmediated in every tested
posture, including DNS-tunnel exfiltration, with no interception
hook measured.

Code touchpoints a follow-up PR would need (read against source, not
implemented): `landlock_impl.rs` handled-rights + netport rules
mirroring the `ConnectTcp` logic (plus the `BindUdp` port-0 grant);
the seccomp DGRAM pin relaxed when UDP rights are handled;
`select.rs`/`ip_eval.rs` — host-agnostic `proto=udp,port=N` allows
stop being dead policy while destination-scoped stays namespaced.

### Verdict — **hold**

Unblock conditions: (a) a `landlock` crate release exposing ABI ≥10
(#140 merged, release pending — or an in-tree uapi implementation);
(b) re-evaluate on a host kernel ≥7.2 — the current reference host
reports ABI 7 and the active LTS line (6.18) cannot reach v10; (c)
adoption limited to host-agnostic UDP port grants; destination rules
stay namespaced; (d) capability matrix updated **only at adoption** —
no matrix change from this investigation. v11 tracepoints/quiet flag
are audit-relevant watch items, not enforcement gains.

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
  failure shape at the same stage. Either way `auto` should
  resolve native-or-refuse per the `select.rs` contract —
  this is a source-trace inference, **not runtime-verified**
  on a restricted host (see Verdict). Admin opt-out is a
  sysctl (host config, out of product scope).
- WSL reference host: neither that sysctl nor
  `kernel.unprivileged_userns_clone` exists; `user.max_user_namespaces
  =15636`; `unshare --user --map-root-user --net` → **OK** —
  namespaced route available here, restriction absent as documented.

### Verdict — **code/documentation consistent; restricted-host runtime unverified**

The documented `auto` semantics match `src/warden/select.rs` —
no doc correction needed. The restricted-host failure shape
above is a code/doc *inference*, not a runtime observation:
no host with `kernel.apparmor_restrict_unprivileged_userns`
enabled was available (the WSL reference host lacks the sysctl
entirely), so behavior under an actual Ubuntu restricted
profile stays **pending real-host testing**.

## Execution summary (record-format fields)

| item | content |
|---|---|
| target | improvement plan §3 R-02 / PR guide PR-11 (baseline `f00e28a`, v0.5.1) |
| environment | Windows 11 Pro 26200.9711 x86-64 non-elevated; WSL2 Ubuntu 24.04.2, kernel 6.18.54.1; mxc-sdk 1.0.1; landlock crate 0.4.7 |
| reproduction | Full sources kept in the durable bundle `.local/pr11-mxc/src/` — `mxc-probe/` (Cargo manifest + `src/main.rs`; `cargo run -- support|run|spawn|proxy`, env toggles `MXC_PROBE_EXE`/`MXC_PROBE_COMMAND`/`MXC_PROBE_BIND`/`MXC_PROBE_ALLOW_ADDR`/`MXC_PROBE_ALLOW_CIDR`/`MXC_PROBE_ALLOW_EXCEPT`/`MXC_PROBE_ALLOW_NOPORT`/`MXC_PROBE_DENY_ADDR`/`MXC_PROBE_NO_LB`/`MXC_PROBE_NO_FS`/`MXC_PROBE_NO_NET`/`MXC_PROBE_NO_WD`/`MXC_PROBE_EXTRA_RO`/`MXC_PROBE_DEFAULT_ENV`/`MXC_PROBE_UI`/`MXC_PROBE_PROXY`/`MXC_PROBE_CAPTURE`/`MXC_PROBE_CAPTURE_ALLOW`/`MXC_PROBE_ISO`/`MXC_PROBE_EGRESS_ALLOW_ALL`/`MXC_PROBE_DENY_CIDR`/`MXC_PROBE_DENY_UDP`/`MXC_PROBE_TIMEOUT_MS`), `winiso-copy/` (the `tests/fixtures/windows_isolation` tree with only `ffi.rs`'s `ole32`→`combase` link-name change, rebuilt `rustc --edition 2021 -O`), `dl.rs` (LoadLibraryW user32/ole32/gdi32 leg), `ui.rs` (clipboard/SendInput/window/system-params probe), `dn.rs` (`ToSocketAddrs` DNS leg), `v6.rs` (v6-capable TCP connect probe — the winiso `attempts` net legs are IPv4-only), `udp.rs` (UDP sendto/connect+send leg), `udprx.rs` (host-side UDP delivery listener), `desk.rs` (window-station/desktop/input-desktop scope probe), `obj.rs` (named-object visibility probe), `gc.rs` (grandchild policy-inheritance shim), `fsx.rs`/`fs2.rs`/`fs3.rs`/`fs4.rs` (fs baseline + `\\?\`/ADS/slash/junction bypass legs), `bind.rs` (container listener / ingress leg), `ipc.rs` (process-enum/token-privilege/HKCU probe), `mxc-json.rs` (raw `__ffi::spawn_container_json` driver — exercises the full wire contract incl. `processContainer.*`), `req-*.json` (the JSON requests used), `udp6.rs`, `fsw.rs` (ambient-write probe), `pipe.rs` (NPFS boundary probe), `icmp.rs`, `acspawn.rs` (named-AppContainer-profile listener spawn — `CreateAppContainerProfile` + `SECURITY_CAPABILITIES`), `bindsid.rs`/`rsid3.rs`/`rsid4.rs` (SID-token probes), `envd.rs` (default-env dump), `hl.rs` (hardlink/symlink/GLOBALROOT/PhysicalDrive/write+exec bypass probe), `xsrv.rs`/`xcli.rs` (cross-container sibling pair), `hello.rs` (user32-free exec probe), `fr.rs` (direct file-read probe), `ipc2.rs` (AF_UNIX/mailslot/raw-socket/UDP-inbound battery), `tcp.rs` (egress precedence/connect probe), `fs5.rs` (fs normalization bypass battery), `tok.rs` (token IL/elevation surface), `fams.rs` (socket-family sweep + self-loopback), `mxc-run.rs` (`mxc_engine::run` run-to-completion driver — Windows Sandbox/hyperlight legs), `ll.py` (`landlock_create_ruleset` version syscall 444). Required inputs: four scratch dirs with `ro-read.txt`/`deny-read.txt`/`ungranted.txt` (probe creates them), a host TCP listener (probe binds it), the winiso `attempts` battery as the child binary; `unshare --user --map-root-user --net` for the userns leg |
| counts | Windows: `support` + 6 attempts-battery `run` legs + 1 `spawn` + ~32 `run` legs + **15 JSON-contract legs via `__ffi::spawn_container_json`** (allowedProxyPeer validation ×4 incl. **positive peer test with a named-profile AppContainer listener**, ui.isolation=desktop, enumeratePaths, learningMode, capabilities, appcontainer backend ×3, DNS under LB=deny, default-env dump, concurrency ×3, **hardlink/symlink/GLOBALROOT/PhysicalDrive/write+exec bypass battery, fs grants ×3, env semantics ×3, cross-container ×2, default-posture network ×3, peer port-scoping, subpath-deny, file-level grant, HKLM surface, ui.isolation handles/atoms gradient, ui clipboard/systemSettings knob legs, capabilities documentsLibrary, deny-except validator leg, `containment:"process"` resolution, windows_sandbox wire check, **AF_UNIX/mailslot/raw-socket/UDP-inbound battery ×2, ingress default×3 + host-connect, egress precedence + allow-except, cwd denied/ambient/ungranted ×3, package-dir persistence, stderr/exit capture, **fs-normalization bypass battery ×11, token IL surface, socket-family sweep ×7 + self-loopback, same-`containerId` sibling connect, **contract-version containment matrix ×9 (0.9/1.0/1.1-alpha × experimental), windows_sandbox run-to-completion real VM launch (+ staging/.wsb inspection, rendezvous-timeout, caller-kill orphan), hyperlight/microvm/wslc run-path rejections**) + host-side `acspawn.rs` (named-profile spawn) — ≈ 190 measured attempt ops + targeted legs, all produced evidence; ole32 bisect 6 exes; Linux: 1 ABI probe + 1 userns leg — pass; macOS: 0 runs — unverified |
| controls | see mapping table + per-target sections |
| audit | `CaptureDenials` **measured both modes**: Block = deny+record (`total_denials:5`); **Allow = learning mode — ungranted access permitted+recorded (`total_denials:11`), explicit denies still enforced**; per-denial JSON (`resource`/`resourceType`/`accessType`/`pid`/`filetime`) + run summary; **gap: `network` denials are NOT captured** (measured — 2 denied connects, 0 network records); ES notify ≠ enforcement; Landlock v7+ audit deltas (v10 quiet flag, v11 tracepoints) are watch items |
| compatibility | node.exe **runs** in tier-1 with `ui.disable=false` — clipboard/system-settings stay denied; `SendInput` lands in the container's **private desktop** (`WinSta0`→`err:5`, `EnumWindows`→0 — but `ui.isolation="desktop"` shares the real desktop: 283 windows reachable — keep `container`); Python ok; **all host-local addresses exempt from egress rules** → proxy mode is the per-destination TCP route, and `allowedProxyPeer` + `hostLoopback=deny` **proven end-to-end at (identity × declared-endpoint) granularity** (named-profile listener reachable; same identity different port `10013`; same endpoint via LAN addr `10013`); **no-network-block default = TCP default-deny** (non-local+loopback+host addr all `10013`, LB default deny → dnscache dead) — **UDP still fully open under that default, v4+v6, on the tested AppContainer-family dispatch** (`"appcontainer"` wire name is an alias re-running the same T1 dispatch; T2/T3 unforceable — equivalence unverified, delivery verified on T1) — biggest measured hole; fs baseline curated-allow **read-only** (system areas ambient, profiles/drives/secrets denied, denies junction/`\\?\`/ADS/hardlink/`GLOBALROOT`-proof, zero ambient writes, `enumerate_paths` = list-without-read, grants lift baseline + deny always wins + **sub-path deny inside granted parent works** + file-level grants work, **write+exec allowed** — no CI); **fs deny on T1 is PSEC-native — no host DACL mutation** (ACE stamping is T2/T3-only, reverted on drop); PhysicalDrive0 blocked; containers can `bind()` listeners (host access gated by `host_loopback` both directions; non-host ingress unverified); named pipes bounded (host/`lsarpc` `err:5`); ICMP blocked; `capabilities` don't override deny rules or open fs (`documentsLibrary` no effect); **egress `to`=NetworkPeer{cidr,except}/`ports`=NetworkPort{port}; deny > allow precedence + allow-except carves exclusions**; ingress schema = `{default, hostLoopback}` only (no rules) — `ingress.default` unmapped in T1 (no measurable effect), host↔container inbound governed by `hostLoopback` bidirectionally (incl. host LAN addr), default posture fail-closed; **all remaining IPC bounded** — AF_UNIX `10013`, mailslots `err:5` both ways, raw TCP `10013`, raw ICMP create-only (send `10047`), **UDP hole was egress-only in the tested listener config** (inbound never delivered there; `hostLoopback=allow` inbound untested — do not generalize to all configs); `cwd` optional + grant-free + denied→System32 fallback; stderr/exit retrievable via Child handle; **package dirs never cleaned** (41 `sandbox.{guid}` accumulated) and **not policy-exempt** (writes denied at AC root + AC\Temp); **fs-deny survives all normalization evasions** (case/8.3 `SECRET~1`/trailing dot-space/fwd slashes/`.\`/`\\??\`/UNC-localhost); **token = Low IL + IsAppContainer=1**; exotic socket families OS-absent (INET/INET6 only); **self-loopback denied — no in-container sidecar**; **same-`containerId` siblings still isolated** (per-spawn identity); **`windows_sandbox` reaches a real disposable-VM launch via run-to-completion** (`1.1.0-alpha`+experimental, .wsb staged, zygote-derived partition live) — streaming spawn rejects it, guest rendezvous unverified (no completion in ~15 min), and **caller death orphans the VM** (SYSTEM vmwp); hyperlight needs WHP (absent), microvm/wslc not compiled; stable request surface fully mapped (lifecycle/telemetry/fallback/ui/captureDenials fields incl. `retainEtl`); captureDenials emits per-event JSON audit records; **PSEC host spec = v1.1 all-bits (flags 0xf, minor 1) — matrix `windows-psec` deficiencies are v1.0-encoder bounds, not OS limits** (spec carries CIDR/ports/protocol/ingress/proxy/peer/fs-grants natively; v1.1 upgrade would close the Windows destination-control gap modulo UDP+names); process/object namespaces private; token = 2 privileges; HKCU own AC hive readable, **HKLM/HKU reads denied by default**; **cross-container isolation complete** (objects/pipes/pids/package-dirs all `err:2/5`, unique `sandbox.{guid}` dirs); destination-scoped UDP impossible at any Landlock ABI; DNS resolves via dnscache only when LB allowed (default/LB=deny → dead; name handling lives in the proxy); **default env = user PROFILE block (persistent vars incl. secrets leak — explicit env mandatory; presence-only `SYSTEMROOT`+`LOCALAPPDATA` minimum; OS appends `Packages\sandbox.{id}` + injects TEMP/TMP)**; ui isolation gradient: `container` private > `handles` (input desktop reachable, windows confined) > `atoms` ≈ `desktop` (283+ windows); several ui knobs no-op on T1 (clipboard:read, systemSettings:parameters); **job object = UI limits + kill-on-close only — no memory/CPU limits**; grandchildren inherit policy + fresh AC SID + win32k mitigation (user32-linked exes `0xC0000142`); `least_privilege_mode` = LPAC attr |
| resources | ProcessContainer launch ≈ **80–85 ms** (`v1::run`, cmd workload); `IsolationSession` launch ≈ **3.4 s**; timeout enforced at +73 ms over request; unmeasured: ES event volume, tier-2/3 launch cost |
| cleanup | scratch probe outside the repo; `.local/pr11-mxc/` evidence only (≈65 files incl. `src/`); probe-spawned listeners/processes terminated, container-spawned grandchildren verified gone (pids no longer exist); repo tree clean; no system settings changed |
| next decision | MXC ProcessContainer: **conditional candidate** — conditions: (a) **effective UDP block outside ProcessContainer rules required before deny-all enforcement can be claimed** (no tier-1 mechanism measured; absent such a block, restrict to policies explicitly permitting unrestricted UDP — operator acceptance alone is an unsafe downgrade, not enforcement; the hole was egress-only *in the tested listener config* — inbound under `hostLoopback=allow` is untested), (b) `ui.disable=false` + `isolation=container` acceptance (SendInput scoped to private desktop — measured; `desktop` shares the real desktop — never select), (c) proxy-mediated TCP egress — **`allowedProxyPeer` + `hostLoopback=deny` proven (identity × declared-endpoint)-scoped** (named-profile peer reachable; same-identity other port `10013`; addr-level bypass `10013`); requires proxy under a named AppContainer profile + DNS moved into the proxy — **verified end-to-end unprivileged on T1** (measured spec prerequisites: peer + no-egress + `privateNetworkClientServer`; r17 ladder + live leg) — on T2/T3 and the AppContainer-runner fallback the proxy path instead needs UAC-elevated `winhttp-proxy-shim` + LoopbackExempt, so tier pinning is mandatory; (d) **explicit env block mandatory** (default = user profile env — persistent-secret leak measured); (e) note gaps: no memory/CPU limits on this surface; T2/T3 fs enforcement mutates host DACLs (`allowDaclMutation` consent); IsolationSession: **disqualified** (no fs/net/env policy surface); **WindowsSandbox one-shot: candidate for the microVM plan's input only** — real VM launch confirmed (`1.1.0-alpha`+experimental, run-to-completion) but streaming I/O unsupported, guest rendezvous unverified on this host, caller death orphans the VM, and its `.wsb` has no per-destination network control (Networking Enable/Disable only) — stronger isolation, weaker control surface; **matrix `windows-psec` upgrade path documented**: host is PSEC v1.1-complete, so the v1.0-only deficiencies (IPv4/32, no ports, no ingress) are liftable by emitting v1.1 spec fields — closes most of the Windows destination-control gap without a backend switch; ES: declined; Landlock v10/v11: hold → crate release (#140 merged, unpublished) + ≥7.2 kernel gates; Ubuntu/`auto`: code/doc comparison only — restricted-host runtime **unverified**, real-host test pending |
