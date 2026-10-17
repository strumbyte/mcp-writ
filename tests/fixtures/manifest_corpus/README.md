# Public-server manifest corpus

Real `tools/list` JSON-RPC responses captured from public MCP servers —
the official reference servers (`@modelcontextprotocol/server-*`,
`mcp-server-*`) plus widely used third-party servers. The corpus is the
regression base for the IronContext CC-001–015 manifest scanner
(`src/verifier/manifest_rules.rs`): `tests/manifest_fixtures.rs` scans
every snapshot and requires the produced findings to match
`expected-findings.json` exactly.

A new blocking finding on a public server means either:

- a rule false positive (fix the rule — improvement plan F-07/F-08), or
- a justified detection (record it in `expected-findings.json` with a
  `note` explaining why the upstream manifest trips the rule).

## Files

- `<name>.tools-list.json` — verbatim `tools/list` response (JSON-RPC
  envelope), pretty-printed.
- `provenance.json` — per-snapshot package, pinned version, source,
  launch argv, fetch date, and license.
- `expected-findings.json` — expected `(rule, severity, tool)` tuples
  per snapshot, each with a written justification note.

## Regenerating

```
python3 scripts/capture-manifest-corpus.py            # all servers
python3 scripts/capture-manifest-corpus.py fetch git  # named only
```

`pinned` entries reuse `tests/fixtures/real_servers/` installs (run its
`setup.sh` / `setup.ps1` first). `npm` / `pypi` entries are installed
ephemerally at the versions pinned in the script — bump the `ServerSpec`
version when a newer upstream release should be captured instead.

Requirements: `node` + `npm` for npm sources, a `venv`-capable
`python3` (or Windows `py` launcher under WSL) for pypi sources.

## Licenses

Tool names and descriptions remain copyrighted by their upstream
projects; snapshots are reproduced here for testing under each project's
license — see `provenance.json` (`license` / `upstream` per entry):

- `@modelcontextprotocol/server-*`, `mcp-server-*` —
  MIT (github.com/modelcontextprotocol/servers)
- `@playwright/mcp` — Apache-2.0 (github.com/microsoft/playwright-mcp)
- `chrome-devtools-mcp` — Apache-2.0
  (github.com/ChromeDevTools/chrome-devtools-mcp)
