# PR-11 MXC evidence bundle (sanitized)

Durable probe sources and wire requests behind
[../successor-mechanisms-2026-11.md](../successor-mechanisms-2026-11.md)
(Target 1 — Windows MXC, GA reassessment on 26200.9711, `mxc-sdk`
1.0.1). Raw probe *outputs* stay in `.local/pr11-mxc/` on the
measurement host (`.local/` is gitignored); this directory carries
everything needed to inspect and re-run the legs.

## Layout

- `src/` — single-file probes, compiled with
  `rustc --edition 2021 -O -o <name>.exe <name>.rs` (see each leg's
  note in the record for which binary it drove). `secv-host.txt` is
  the captured `QueryProcessSecurityEnvironmentSupport` flags dump.
- `src/mxc-probe/` — the SDK driver crate
  (`cargo run -- support|run|spawn|proxy`; per-leg behaviour is
  toggled by the `MXC_PROBE_*` env vars listed in the record's
  execution-summary `reproduction` row).
- `req/requests.json` — the `__ffi::spawn_container_json` wire
  requests used by the `mxc-json.rs` raw-driver legs, merged into a
  single object keyed by leg name (`req-<name>` — e.g.
  `"req-dns-lbdeny"`).
- `winiso-copy/` is **not** duplicated here — it was a working copy
  of `tests/fixtures/windows_isolation/` with only `ffi.rs`'s
  `ole32`→`combase` link-name change; the committed fixture tree is
  the durable source for the direct-PSEC legs.

## Sanitization

Host-specific literals from the measurement host were substituted
before commit; everything else is verbatim.

| Original | Replaced with |
|---|---|
| `C:\Users\yuzame.AzureAD`, `yuzame` (profile/username) | `probe.user`, `probe` / `%USERPROFILE%`-derived (sources take the home dir from `USERPROFILE`/`USERNAME`) |
| `YUZAME~1.AZU` (8.3 short-name in `%TEMP%` paths) | `PROBE~1` |
| `192.168.11.238`, `192.168.11.10`, `192.168.11.0/24` (host LAN) | `192.0.2.238`, `192.0.2.10`, `192.0.2.0/24` (TEST-NET-1) |
| `fd04:4aa7:2c88:9e00::1` (host ULA) | `fd00::1` |
| `S-1-15-2-1330091309-…` (real AppContainer SID) | `S-1-15-2-EXAMPLE` |

To re-run a request verbatim, substitute back the operator's own
profile path / host addresses — the sanitized values are deliberately
non-routable documentation ranges.

## Reproduction notes

- `mxc-probe` legs: `cargo run -- <mode>` inside `src/mxc-probe/`
  with the `MXC_PROBE_*` env toggles from the record.
- Raw-wire legs: extract the leg's object from `req/requests.json`
  into a standalone file and run `mxc-json.exe <file>` after building
  `src/mxc-json.rs` (needs the `mxc-sdk` crate for `__ffi`).
- Single-file legs: each `.rs` is a standalone `rustc` binary run
  either inside the spawned container (`MXC_PROBE_EXE` /
  `MXC_PROBE_COMMAND`) or on the host as a listener/counterparty.
- Direct-PSEC legs: `tests/fixtures/windows_isolation/` built with
  `rustc --edition 2021 -O` (see `ffi.rs` for the `combase` link
  name used on this host).
