# Manual VM validation jobs (PR-25)

Each adopted VM method has an owned, manually dispatched validation job.
Hosted runners cannot supply the virtualization these methods need, so
the jobs run on self-hosted runners — or interactively, with the same
scripts — and leave a durable evidence bundle per run.

| Method | Script | Test target | Workflow job / `runs-on` labels |
|---|---|---|---|
| Kata Containers | `scripts/validate-kata.sh` | `kata_vm_e2e` | VM tests `kata` — `[self-hosted, linux, kata]` |
| Apple `container` | `scripts/validate-apple-container.sh` | `apple_container_vm_e2e` | VM tests `apple-container` — `[self-hosted, macos, apple-container]` |
| Hyper-V isolated containers | `scripts/validate-hyperv.ps1` | `hyperv_vm_e2e` | VM tests `hyperv` — `[self-hosted, windows, hyperv]` |
| Windows Sandbox | `scripts/validate-windows-sandbox.ps1 -Vm` | `windows_sandbox_vm_e2e` | VM tests `windows-sandbox` — `[self-hosted, windows, windows-sandbox]` |
| WSL Containers (`wslc`) | `scripts/validate-wslc.ps1` | `wslc_container_e2e` | VM tests `wslc` — `[self-hosted, windows, wslc]` |
| Windows native mechanisms (AppContainer/PSEC) | `scripts/validate-windows-isolation.ps1` | `windows_isolation_e2e` | VM tests `windows-isolation` — `[self-hosted, windows, winiso]` |

The last row is deliberately not a VM method: `windows_isolation_e2e`
runs a golden contract layer anywhere plus live fixture and product
legs on a Windows host (the AppContainer baseline and the opt-in PSEC
path), and records the same
`environment-unavailable`/`failed`/`winiso-tests-passed` result shape
under `.local/winiso-validation/<run>/`. Insider/preview lab legs stay
behind the script's `-Lab` switch and are recorded as not-run
otherwise — a `winiso` runner is an ordinary retail Windows host; the
lab host is a separate, never-required environment.

## Per-job environment requirements

Each runner host must independently satisfy the contract below *before*
registration — the jobs assume nothing about hosted-runner images and
fail closed on a shortfall rather than guessing.

| Job | OS / arch | Virtualization | Interactive logon | Elevation | Free disk |
|---|---|---|---|---|---|
| `kata` | Linux x86-64 | `/dev/kvm` + `/dev/vhost-vsock` (nested virt on the host, e.g. WSL2) | not required | docker group access | ≥ 40 GiB on the cargo-target and test-root filesystems |
| `apple-container` | macOS arm64 (≥ 26) | Apple `container` system running | runner session | user | ≥ 40 GiB |
| `hyperv` | Windows x86-64 | Windows-mode dockerd (`OSType=windows`) + `vmcompute`/`hns` | interactive session | docker access | ≥ 40 GiB on run/TEMP drives |
| `windows-sandbox` | Windows x86-64 | `Containers-DisposableClientVM` feature + Store `wsb` CLI | required | non-elevated measured | ≥ 40 GiB on run/TEMP drives |
| `wslc` | Windows x86-64 | WSL product ≥ 2.9.3 (per-user session VM) | required (sessions are per-user) | non-elevated measured | ≥ 40 GiB on the `MCP_WRIT_WSLC_*` write drives + ≥ 2 GiB under `%LOCALAPPDATA%` |
| `windows-isolation` | Windows x86-64 retail | none — native OS mechanisms | required (Session ≠ 0) | non-elevated measured; elevation recorded | ≥ 40 GiB on run/TEMP drives |

Admin rights are *recorded*, never required: every measured leg ran
non-elevated, and a runner running elevated is not a defect — but a job
that silently required elevation would break the contract. An
all-skipped leg set is a `failed` result, not a pass.

Dispatch `VM tests` (`.github/workflows/vm-tests.yml`) with the `method`
input — `all` or a single method. The workflow is `workflow_dispatch`
only; no push/PR triggers and no `workflow_call`, so Release never
implies VM acceptance. A method's environment belongs to its own job —
a missing Kata host cannot become an Apple pass, and no job substitutes
a weaker isolation boundary.

## Runner setup

Register a self-hosted runner per virtualization host with the labels
above (repo or org runner → Settings → Actions → Runners). The runner
host must independently satisfy the method's environment contract in
its validation doc (engine/runtime registration, `/dev/kvm` +
`/dev/vhost-vsock` for Kata, `container system` running for Apple,
`OSType=windows` dockerd for Hyper-V, the Sandbox feature + `wsb` CLI +
interactive session for Windows Sandbox, and for `wslc` a WSL product
version ≥ 2.9.3 with a resolvable `wslc` CLI (PATH, the product-install
path `C:\Program Files\WSL\wslc.exe`, or `MCP_WRIT_WSLC_EXE`) plus an
interactive logon — sessions and their stores are per-user/
elevation-scoped). Rust is installed by the job's pinned toolchain
step.

## Result states and the fail-closed rule

Every job ends in exactly one recorded state:

- `vm-tests-passed` — all gated tests executed and passed, and the
  evidence checks below found every required file.
- `failed` — the tests ran and failed, the environment gate failed, the
  expected test count was not met, required evidence was absent, or
  work-directory cleanup failed.
- `environment unavailable` — used in `docs/test-matrix.md` records when
  the run could not start at all; never reported as a pass.

`scripts/validate-*` sets the method's `MCP_WRIT_REQUIRE_*_TESTS=1`
before invoking cargo, so a prerequisite skip inside the suite fails
the job instead of passing unexecuted. After the suite, the script
compares the executed-test count (parsed from `test result:` lines)
against the known suite size and fails on a shortfall or on `ignored`
tests — an unexecuted leg is not a pass. Evidence completeness is then
checked per session directory: missing `metrics.json` /
`lifecycle.json` / `report/report.json` / `logs/audit.jsonl` / product
`host-*-report.json` / `host-identity.json` fails the run.

## Run directory layout

```
.local/<method>-validation/<utc>-<uuid>/
├── work/                  # scratch root (deleted at the end of a run)
├── evidence/              # per-session allowlisted copies, kept
│   └── <session dir>/
│       ├── metrics.json         # tier (vm|product|harness), timings, memory
│       ├── lifecycle.json       # unit id, teardown/refusal outcome
│       ├── host-identity.json   # product sessions: engine/runtime + unit
│       ├── report/…             # guest + host launch reports
│       └── logs/audit.jsonl
├── test-output.txt        # the cargo test log
└── result.json            # machine-readable run summary
```

`result.json` records the exact commit, host OS/kernel/arch, toolchain,
engine/runtime and image versions, test counts, evidence counts, the
result state, and SHA-256 source hashes of the test, scripts, backend,
and fixtures — enough to reproduce or audit the run later. The `work/`
tree is deleted at the end of every run; `evidence/` stays and is
uploaded as a workflow artifact (`*-validation-<run>-<attempt>`) with
`if: always()`, so failures keep their evidence too.

The tests write into `$MCP_WRIT_<METHOD>_TEST_ROOT` (a scratch `work/`
dir — for Kata a `mktemp` dir on the system temp filesystem, because
virtiofs cannot share WSL2 `/mnt/*` mounts into the guest) and each
session copies an allowlist into `$MCP_WRIT_<METHOD>_EVIDENCE_DIR`
(see `common::copy_session_evidence` / `copy_evidence_files` in
`tests/common/mod.rs`). Credentials, staged executables, workspace
payloads, and arbitrary RPC bodies are never part of the allowlist.
Without those variables, sessions use `target/<method>-tests/` — the
system temp dir for Kata — and copy nothing, so local development
skips stay cheap.

## Local reproduction

Run the same script the job runs, on a host meeting the method's
environment contract:

```bash
scripts/validate-kata.sh            # Linux + docker + kata runtime
scripts/validate-apple-container.sh # macOS arm64 + container system
scripts/validate-hyperv.ps1         # Windows + OSType=windows dockerd
scripts/validate-windows-sandbox.ps1 -Vm
scripts/validate-wslc.ps1           # Windows x86-64 interactive + WSL >= 2.9.3 + wslc
scripts/validate-windows-isolation.ps1  # Windows x86-64 interactive retail host
```

A failed run still leaves `result.json` (with `error`) and whatever
evidence was produced. Record the outcome — pass, fail, or
`environment unavailable` — in `docs/test-matrix.md` with the commit
and environment.
