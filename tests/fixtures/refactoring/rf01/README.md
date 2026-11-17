# RF01 reproduction inputs — audit classification

`validation_kind()` (`src/auditor/checker.rs`) classifies a
`PolicyViolation` by substring-matching `reason`: any reason containing
`path traversal` is reported as `ValidationPathTraversal`, and
`is_denied_target()` recognizes target denials by `path '…'`/`host '…'`
prefix plus the producer's terminal phrase. Because the denied path's
own spelling is embedded in the reason, user input steers the audit
classification — the bug RF01 fixes.

`requests.jsonl` holds `tools/call` lines; `policy.json` holds the
matching policy template. The regression test (to be added in RF01's
PR, not RF00) creates a write-restricted dir, substitutes `${ROOT}`
with its canonical spelling, and runs `check_request` with cwd=`ROOT`.

| line | input shape | produced reason (current code) | classification effect |
|---|---|---|---|
| 1 | `tree/allowed/ok.txt` | pass | baseline |
| 2 | `tree/../escape.txt` | `path '…' (resolved '…') not in tool fs allowed paths` | true out-of-scope target denial |
| 3 | `tree/path traversal report/x.txt` | `path 'tree/path traversal report/x.txt' … not in tool fs allowed paths` | **misclassified** — `contains("path traversal")` → `ValidationPathTraversal`, not a target denial |
| 4 | `tree/it's.txt` | `path 'tree/it's.txt' … not in …` | quote inside the `path '…'` wrapper |
| 5 | `tree/x') denied by tool fs sub-policy` | `path '…') denied by tool fs sub-policy' … not in …` | embedded terminal phrase; `ends_with` still keys on the real suffix |
| 6 | `tree/y') not in tool fs allowed paths` | same shape as 5 | second embedded suffix variant |
| 7 | `secrets/key.pem` | `path '…' (resolved '…') denied by tool fs sub-policy` | true `denied by` target denial |
| 8 | `../escape/passwd` | `path '…' (resolved '…') not in tool fs allowed paths` | escape spelling → ordinary out-of-scope denial (no traversal kind) |
| 9 | `"path":42` | `schema validation failed:` | `ValidationArgumentInvalid` baseline |
| 10 | `unknown_tool` | `tool not found in policy (default deny)` | authorization baseline — wire-collapsed with 11 |
| 11 | `write_file` | `tool is not allowed` | authorization baseline |

True-positive comparators (session-path traversal `path traversal
detected in '…'`, schema-file traversal `path traversal: schema file
…`) live behind session/schema-file loading rather than `tools/call`
lines; the RF01 PR reproduces them through the session/policy loader
entry points, using the same prepared root.

Recorded in RF00 (`run-2026-11-17-01`); the classification verdicts
these inputs produce belong to RF01's own diff, not this baseline.
