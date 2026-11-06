# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's **private
vulnerability reporting** on this repository: open the repository's
*Security* tab and choose *Report a vulnerability*. Do not file public
issues, pull requests, or discussions for unpatched vulnerabilities.

A report is most actionable with the affected version or commit, the
policy and command line used, the boundary the behavior crosses, and a
reproduction or trace.

- **Acknowledgement:** we aim to confirm receipt within **7 days**.
- **Initial assessment:** we aim to return a first severity and
  affected-surface evaluation within **14 days** of confirmation.

These are targets, not guarantees — the project is maintained by a
small team.

## Scope

Covered:

- the **latest published release** — see the repository's Releases
  page; and
- the **`main` branch** at the time of the report.

Not covered:

- **PoC / opt-in launch paths** — `unotify-run`, `namespaced-run`,
  `ebpf-run`, and `macos-proxy-run` are proof-of-concept or privileged
  opt-in routes documented as such in the
  [user guide](docs/guide.md#4-subcommands). They carry no support
  commitment, but a report describing a security weakness in them
  still goes through the private channel above — ordinary public
  issues are for non-security reports only.
- Weaknesses reachable only while a documented downgrade is armed —
  `--dry-run`, `MCP_WRIT_SKIP_SANDBOX`,
  `--unsafe-unsandboxed-discovery`, `MCP_WRIT_ALLOW_REPLACEABLE_PATHS`,
  `MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS`, `sandbox allow_degraded=#true`,
  or `inherit-parent #true`. Each exists to weaken a boundary the docs
  already disclose.
- Releases older than the latest — only the latest release and `main`
  carry this commitment.

## Disclosure

We coordinate disclosure with the reporter. The report stays private
until a fix ships in a release or we agree on a disclosure date, and
we credit reporters in the release notes unless you ask us not to.
Please give us a reasonable window before publishing details — if we
go unresponsive past the timelines above, a reminder on the same
private thread is the right nudge.
