# Writing a policy

[日本語](policy-authoring.ja.md) / [Command and policy reference](guide.md#5-policy-reference)

This guide builds an MCP server policy the way deployments converge on one:
launch from a narrow default-deny base, exercise the server, read the denials
in the audit log, add only the clauses those denials confirm, and re-pin the
difference. `generate-policy` is one way to obtain a starting draft — its
output can leave tool definitions and required runtime permissions
incomplete, so saving it does not mean the policy is ready to use.

If you already have a draft, start with [editing permissions](#editing). You can also jump to [recipes](#recipes), [verification](#verification), or [troubleshooting](#troubleshooting).

## 1. Identify the server and the operations to allow

Start with one policy file per server so that its permissions are easy to follow. Record the following information.

| Item | What to identify |
|---|---|
| Launch command | Executable, script, arguments, and working directory. Use the same command as normal operation |
| Actual tool names and arguments | Check the server documentation or `tools/list` in an MCP client; do not guess names such as `read_file` |
| Runtime files | Executable, Python/Node runtime, libraries, certificates, and configuration files |
| Tool input directories | For example, `/srv/mcp-data/public/`. Consider these separately from runtime files |
| Write destinations | Create a dedicated output directory only when writes are needed |
| Network destinations | Whether outbound access is needed, the URL/host arguments tools accept, and their actual destinations |

Use absolute paths for filesystem permissions. On Windows, forward slashes such as `C:/mcp/data/**` avoid backslash escaping in KDL.
Permissions inside a container use paths inside that container. The file passed to `--policy` is a path on the side launching the guard.
Create directories that need OS grants, including output directories, before starting the server.

## 2. Start from a narrow default-deny policy

The starting file should grant little more than launching the server:
runtime read paths, the tools you intend to use, and deny-by-default
everywhere else. There are three ways to get there; whichever you choose,
copy the base to `policy.kdl` so later regeneration never overwrites the
reviewed file:

```sh
cp policy.draft.kdl policy.kdl
```

In PowerShell, use `Copy-Item -LiteralPath policy.draft.kdl -Destination policy.kdl`.
Regenerate into a separate file later so that you do not overwrite the reviewed `policy.kdl`.

### Extending a reviewed example

`examples/policies/` carries reviewed policies for four pinned real MCP
servers — `filesystem.kdl`, `memory.kdl` (Node), `time.kdl`, and `git.kdl`
(Python) — each pinned to the observed tool surface with a
`tools-list-hash`. They contain no host paths on purpose. A deployment
policy extends one of them and adds the host's `defaults` (interpreter read
paths, data roots) plus its `server`-scoped tool rules:

```kdl
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "/usr/lib/node" mode="read"          // resolved node prefix
        allow "/srv/mcp/node_modules" mode="read"  // server package tree
        allow "/srv/data" mode="read"
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" {
        filesystem { allow "/srv/data/**" }
    }
}
```

`extends` paths resolve relative to the file that contains them, and chains
work: each example extends `runtime/node.kdl` or `runtime/python.kdl`.
These runtime files carry two things: the interpreter's observed syscall
allowlist (`defaults.syscalls` — a Linux seccomp list; it is not applied on
macOS/Windows, where enforcement comes from the sandbox-exec profile and
AppContainer grants instead) and comments listing the read paths a host
must add. Runtime policies are meant to be shared as-is; server policies
pin the tool surface; host policies supply the paths.

`scripts/check-server.sh` / `scripts/check-server.ps1` sanity-check the
result without Cargo: they run a dry-run handshake and `tools/list`, the
same exchange sandboxed, and optionally one `tools/call`, exiting non-zero
if any stage fails. See [Development](development.md#real-mcp-server-verification).

### Writing a minimal skeleton

When no reviewed example matches the server, start from a skeleton that
allows only launch-time reads and declares the tools you identified in step
1:

```kdl
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
server "my-server" {
    tool "read_file" side_effect="read_only"
}
```

### Generating a draft

`generate-policy` is another starting point, not a finished policy. Begin
with static inspection, which does not execute the server. Replace the
command and paths below with your actual server.

```sh
mcp-writ generate-policy --output policy.draft.kdl -- python /opt/mcp-server/server.py
```

For a native ELF or Mach-O binary, use `-- /opt/mcp-server/my-mcp-server`; for JavaScript, use `-- node /opt/mcp-server/server.js`.
Native inspection handles ELF (x86-64 / AArch64 Linux) and Mach-O (arm64 Darwin) files, not Windows `.exe` (PE) files.
Source inspection also depends on supported registration and handler patterns. If dynamic registration or a command such as `python -m` prevents source identification, fill in tools from their actual definitions.
`--project <dir>` adds hints from dependencies and project files; it does not guarantee complete tool detection or permissions.

To execute the server and retrieve tool definitions and schemas, write a separate draft:

```sh
mcp-writ generate-policy --live-discovery --output policy.discovered.kdl -- python /opt/mcp-server/server.py
```

`--live-discovery` restricts environment variables but does not run discovery inside an OS sandbox. Use a server you have decided to execute in a test environment.
If discovery fails because credentials or other environment variables are absent, you can also write the policy manually. Normal `run` inherits its parent's environment variables.

Check a generated draft for the following before adopting it as the base:

- If `server` / `tool` entries are absent, add the actual tools you intend to use. Tools absent from the policy are denied.
- If `filesystem` has no allowed paths, add runtime files and tool data paths.
- Review the reasons in `REVIEW` / `WARNING` comments. Unbound handlers or tools without sufficient evidence may have no `side_effect`.
- Review and retain `args_schema` and `tools-list-hash` obtained from live discovery. Do not invent a hash value.
- The draft also pins the launch target inside `server "auto-generated"`: `binary-hash` covers the resolved `argv[0]` (the native binary, or the interpreter for `python server.py` / `node index.js`), and `entrypoint-hash` covers a script payload's first argument. These digests cover **this host's** files — the REVIEW comments beside them tell you to recompute the hashes on the deployment host (`generate-policy` there again, or hash the same targets) and to regenerate the draft whenever the server or its interpreter is updated. When the launch target cannot be bound — `python -m <module>`, `npx <pkg>`, or inline eval (`-c` / `-e` / `--eval` / `--command`) — no hash is emitted for the payload; a `// REVIEW:` comment records the reason instead. Never fill in a guessed hash: `run` fails closed when a `binary-hash` target does not canonicalize to the launched executable, when an `entrypoint-hash` target is neither the executable nor its first payload argument, when a digest mismatches, and when the only entries are `lockfile-hash` / `docker-manifest-hash` or the argv is inline eval.

`--self-test` is an optional diagnostic of a newly generated draft. It does not load an edited policy file for verification. Verify your edited policy in [step 3](#verification).

<a id="verification"></a>

## 3. Exercise the server and read the denials

Create test data: `hello.txt` inside the allowed directory and a harmless file outside that scope. Testing with real secret files is unnecessary.
The following starts the Linux read example. Create the audit log's parent directory somewhere writable by the user running the guard.

```sh
mcp-writ run --dry-run --policy /opt/mcp-config/policy.kdl --audit-log /opt/mcp-logs/dry-run.jsonl -- /opt/mcp-server/my-mcp-server
```

For the Windows example, use PowerShell:

```powershell
mcp-writ run --dry-run --policy C:/mcp/config/policy.windows.kdl --audit-log C:/mcp/logs/dry-run.jsonl -- C:/mcp/server/my-mcp-server.exe
```

Starting these commands in a terminal alone does not exercise tool checks. Configure an MCP client to launch the guard over stdio, obtain `tools/list`, and call the tools through that client — see
[Client configuration](../README.md#client-configuration) for the
`command` / `args` / `env` shape each client expects (VS Code uses a
top-level `servers` key instead of `mcpServers`).
If the client cannot find `mcp-writ` on PATH, use its absolute executable path in `command`.
For policies containing multiple `server` blocks, add a selection such as `--server files`. This selects the name in KDL, not the client's display name.

### What to check in dry-run mode

Dry-run runs the server without OS sandboxing and forwards calls that the policy would normally deny, so execution may have side effects such as file changes or network communication. Use test data.
Manifest checks at the configured `--fail-on` threshold and hash mismatches can still stop the session.

Exercise these operations on a server implementing the relevant tools. A server's own error for an unimplemented tool does not count as a guard denial.

| Call | Expected result in a normal run |
|---|---|
| `read_file` with `/srv/mcp-data/public/hello.txt` | Success |
| `read_file` with `/srv/mcp-data/outside.txt` | Guard denial |
| `read_file` without a path | Guard denial |
| A denied `write_file` / `exec_shell` | Guard denial |
| Write recipe: `write_file` with the absolute path of `output/result.txt` | Success; writes under `public` are denied by the guard |
| API recipe: `fetch_url` with the allowed host / another host | Allowed host passes RPC checks; another host is denied by the guard |
| `tools/list` | Only policy-allowed tools are listed; denied and unlisted tools are hidden |

On Windows, substitute the corresponding `C:/mcp/data/...` file paths. Passing API RPC checks and completing an authenticated network request are separate results to verify.

`tools/list` itself is also filtered in a normal run — the client sees only policy-allowed tools. Dry-run forwards the full advertised set instead and records a `tools_list.filtered` event with `action: "observed"`. When you widen the allowlist later, the client must fetch `tools/list` again: a previously fetched list does not gain the newly allowed tools on its own.

### Reading the audit log

Inspect `event_type`, `action`, `target_tool`, and `details` in the audit log. This illustrative excerpt contains only the fields needed for diagnosis:

```json
{"event_type":"tool_call.denied","action":"observed","target_tool":"read_file","details":"path '...' not in tool fs allowed paths"}
```

`action="observed"` records a violation forwarded during dry-run. A returned tool result does not necessarily mean the policy allowed the call.
Use `details` to adjust the relevant tool, path, or host so that only intended operations pass.

<a id="troubleshooting"></a>

### Finding the setting behind a denial

| Symptom or message | What to check |
|---|---|
| `tool not found in policy` / `tool is not allowed` | Actual tool name, selected `server`, `deny=#true`, and whether the draft had any tools |
| `filesystem-restricted tool is missing a path target` | Argument names and structure. For path-free tools, use the dedicated `allow none=#true` + `require-path #false` configuration |
| `not in tool fs allowed paths` | Effective tool allowlist, absolute paths, and symlink targets. Adding global permissions alone may not change this result |
| `network-restricted tool is missing a url/host target` / `not in tool network allowed hosts` | Actual arguments and `tool.network`, including tools whose fixed destination is absent from arguments |
| `Error loading policy` / `side_effect` consistency error | KDL types, duplicate tools, inherited write grants, and explicit network settings. Booleans are `#true` / `#false` |
| `--audit-log <path> is required` / log cannot be opened | `logging.fail_closed` defaults to true. Check the log path, parent directory, and write permissions |
| Linux: `syscalls.allowed must include execve` | Explicit startup syscall allowance, separately from the `exec_shell` RPC tool |
| Only normal startup fails, or the server reports `EACCES` / `EPERM` | Executable, libraries, data, output paths, and syscalls. Dry-run success does not verify OS restrictions |
| Windows rejects a host allowlist | Separate OS network access and `tool.network`; see the [API recipe](#api-access) |
| macOS: `macOS SBPL cannot pin remote host` | Only loopback TCP ports are expressible in deny-all mode; move host checks to `tool.network` and open OS access, or use deny-all |
| `declares per-tool syscalls, which are not enforced` | Move the syscall rules to `defaults.syscalls`; they are process-wide and Linux-only |
| Manifest finding `CC-...` / tool definition hash mismatch | Changes in server descriptions, schemas, or versions. Broader filesystem grants do not fix these |

<a id="editing"></a>

## 4. Add only the confirmed clauses

Each denial read in the audit log maps to one setting. Add only the clauses
the exercised operations actually need — for example, this kind of draft does not yet establish allowed read locations or the OS permissions needed to start the server:

```kdl
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
server "auto-generated" {
    tool "read_file" side_effect="read_only"
}
```

Edit each setting according to its role:

| Location | Purpose |
|---|---|
| `defaults.filesystem` | Files the server process actually opens: runtime and data paths, with read or read/write access |
| `defaults.syscalls` | Linux seccomp allowlist for the whole process; not applied on macOS/Windows |
| `defaults.network` | Shared network configuration; OS enforcement differs by platform — see the [per-OS enforcement matrix](guide.md#per-os-enforcement-matrix) |
| `tool` inside `server` | Allowed tools and the paths, hosts, and schemas accepted in their RPC arguments |

Windows and macOS grant OS file access from global settings only. Linux also adds allowed tools' file permissions to Landlock.
All of these are process-wide grants. The OS sandbox does not switch for each tool call. Declare shared runtime permissions explicitly, then narrow each tool's arguments to its intended scope.

### Inheritance and replacement

Tool settings are merged in the order `defaults → profile → server-defaults → tool`.
An explicit allowlist in a later `filesystem` or `network` layer replaces the earlier allowlist; it does not simply append to it.
Omitted allows inherit earlier settings, while explicit denials accumulate. A later `allow` cannot undo an existing `deny`.

For example, even if startup needs `/opt/mcp-server/**`, putting only `/srv/mcp-data/public/**` in `read_file`'s `filesystem` narrows that tool's RPC paths to the latter directory.
Use `allow none=#true` to clear inherited path grants. An empty `filesystem {}` does not clear the allowlist.

<a id="linux-read-only"></a>

### Edited example: reading files on Linux

This example installs the server under `/opt/mcp-server/` and lets `read_file` read only `/srv/mcp-data/public/`. Save it as `policy.kdl`.
Check library locations and required syscalls for your server, CPU, and runtime. The syscall list is a starting point, not a list that starts every Python/Node/Go server.

```kdl
policy version=1

defaults {
    filesystem {
        allow "/opt/mcp-server/**" mode="read"
        allow "/usr/lib/**" mode="read"
        allow "/lib/**" mode="read"
        allow "/srv/mcp-data/public/**" mode="read"
        secret-overlay #true
    }
    syscalls {
        allow "read" "write" "openat" "close" "fstat" "newfstatat"
        allow "mmap" "munmap" "mprotect" "brk" "pread64" "lseek"
        allow "rt_sigaction" "rt_sigprocmask" "rt_sigreturn" "futex"
        allow "set_tid_address" "set_robust_list" "rseq" "arch_prctl"
        allow "getrandom" "prlimit64" "execve" "exit" "exit_group"
    }
    network {
        deny host="*"
    }
}

server "files" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "/srv/mcp-data/public/**" mode="read"
        }
    }
    tool "write_file" deny=#true
    tool "exec_shell" deny=#true
}

logging level="info" fail_closed=#true
```

`mode="write"` means read/write; the default `mode="read"` is for reading.
`side_effect="read_only"` checks configuration consistency and rejects host/URL arguments. It does not prove that the server's implementation only reads data.

Normal Linux startup requires an explicit `execve` or `execveat` allowance. That permission remains in the child process, so distinguish it from denying the `exec_shell` RPC tool.
An interpreter also needs read access to its executable, standard library, and dependencies. Allowing `/opt/mcp-server/**` alone does not grant access to a Python or Node installation elsewhere.
For a native ELF or Mach-O binary, inspect syscall candidates with `mcp-writ inspect --format json /opt/mcp-server/my-mcp-server`. Static inspection cannot cover every execution path or dynamic library, so verify with a normal run.

A policy that allows an entire parent directory and tries to exclude a secret subdirectory with `deny` is rejected at load time because Landlock cannot express that restriction. List separate directories that may be accessed instead.

<a id="recipes"></a>

## 5. Adapt the policy to the workload

<a id="write-output"></a>

### Writing to a dedicated output directory

Add this line to `defaults.filesystem` in the Linux example, keeping the existing read grants:

```kdl
allow "/srv/mcp-data/output/**" mode="write"
```

Replace `tool "write_file" deny=#true` with this block. Do not add a duplicate tool with the same name.

```kdl
tool "write_file" side_effect="write" {
    filesystem {
        allow "/srv/mcp-data/output/**" mode="write"
    }
}
```

`side_effect="write"` alone does not grant write access. Check `mode="write"` and the actual write-related syscalls required.
The `read_file` RPC still accepts paths only under `public`, but the whole server process can now write to `output`.

<a id="windows-files"></a>

### Reading and writing files on Windows

This is a standalone policy for an executable and dependencies under `C:/mcp/server/`, with data under `C:/mcp/data/`. Save it as `policy.windows.kdl`.
If the runtime is installed elsewhere, also add its actual location to the global read grants. Linux syscall lists do not configure AppContainer.

```kdl
policy version=1
defaults {
    filesystem {
        allow "C:/mcp/server/**" mode="read"
        allow "C:/mcp/data/public/**" mode="read"
        allow "C:/mcp/data/output/**" mode="write"
        secret-overlay #true
    }
    network {
        deny host="*"
    }
}
server "files" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "C:/mcp/data/public/**" mode="read"
        }
    }
    tool "write_file" side_effect="write" {
        filesystem {
            allow "C:/mcp/data/output/**" mode="write"
        }
    }
    tool "exec_shell" deny=#true
}
logging level="info" fail_closed=#true
```

Path matching is case-insensitive. Linux paths such as `/srv/...` are not automatically converted to `C:/...`.
Use directories managed by the running user where AppContainer ACL grants can be applied.

<a id="api-access"></a>

### Calling an external API

The following standalone example is for Windows. It assumes that `fetch_url` accepts arguments such as `{"url":"https://api.example.com/status"}`. Replace the host and tool names, then save it as `policy.api.kdl`.

```kdl
policy version=1
defaults {
    filesystem {
        allow "C:/mcp/server/**" mode="read"
        secret-overlay #true
    }
    network {
        allow host="*"
    }
}
server "api" {
    tool "fetch_url" side_effect="network" {
        filesystem {
            allow none=#true
            require-path #false
        }
        network {
            allow host="api.example.com"
        }
    }
    tool "exec_shell" deny=#true
}
logging level="info" fail_closed=#true
```

Windows AppContainer cannot filter connections by hostname. This example opens OS network access and uses the Auditor to restrict hosts in RPC arguments.
A hostname allowlist combined with `deny host="*"` in `defaults.network` is a load error on Windows.
This example does not restrict arbitrary internal connections or redirect destinations inside the server. Host checks also do not restrict URL schemes or ports.

On Linux, adapt the filesystem paths and startup syscalls, and check required network syscalls such as `socket` / `connect`. TLS access may also need read access to certificates and DNS configuration.
A bare port entry such as `allow host="443"` becomes a Landlock rule for that port to any host; hostname entries are skipped with a warning and stay Auditor-only.
On macOS, only loopback TCP ports can be pinned in deny-all mode and a remote hostname fails the spawn.
See the [per-OS enforcement matrix](guide.md#per-os-enforcement-matrix) and the [reference](guide.md#field-reference) for OS and RPC network constraints.

Do not apply this `tool.network` example unchanged to a tool that calls a fixed API without receiving a URL/host argument: calls with no host are also denied. The Auditor cannot verify a destination absent from the arguments; consider the server implementation and network controls in its execution environment.

### Restricting environment variables passed to the server

By default the child server inherits the full environment of the `mcp-writ run` process — including variables a client sets through its `env` configuration (for example API keys) and anything ambient in the shell. To pass only a chosen set of variables, declare an allowlist under `defaults.environment`:

```kdl
defaults {
    environment {
        allow "MEMORY_FILE_PATH"
    }
}
```

When the `environment` node is present — even when empty — the child receives only:

- `PATH`, when the parent has it
- the Windows system variables (`SYSTEMROOT`, `WINDIR`, `PATHEXT`, `COMSPEC`, `SYSTEMDRIVE`, `LOCALAPPDATA`) on Windows
- `TMPDIR` / `TMP` / `TEMP`, overridden to the private temp directory only when the launch path assigns one — macOS sandboxed spawns, self-test, and live discovery. (On Windows, AppContainer remaps the temp variables to the container-private `AC\Temp`.) Other runs inject no temp-dir variable at all
- each listed `allow` name, copied from the parent environment — a listed name that is not set on the parent stays unset in the child

Every other variable is dropped, so client-supplied `env` entries (API keys, tokens) reach the server only when explicitly listed. Without an `environment` node, the parent environment is inherited unchanged.

There is no `sandbox tmpdir=` knob: on regular Linux/Windows runs the child receives no `TMPDIR`/`TMP`/`TEMP`, so runtimes fall back to their built-in defaults (for example `/tmp`, which is writable only if `defaults.filesystem` grants it). A server that needs a temp directory under restriction should list `TMPDIR`/`TMP`/`TEMP` in the allowlist to inherit the parent's values, together with a filesystem write grant for that path.

Listed names are matched case-insensitively on Windows (`allow "path"` passes `PATH`); on Linux and macOS the lookup is exact.

The example above is what `@modelcontextprotocol/server-memory` needs: the server reads `MEMORY_FILE_PATH` to locate its data file and falls back to `memory.jsonl` inside its own package directory when the variable is missing — which typically fails because the package directory is not writable inside the sandbox. Listing `MEMORY_FILE_PATH` in `defaults.environment` (and setting it in the client `env` block or the parent shell) makes the configured location reachable.

Environment restriction is part of the launch contract, not the OS sandbox: it applies identically on Linux, macOS, and Windows, including `--dry-run` runs and `MCP_WRIT_SKIP_SANDBOX=1` runs. `environment` is a process-wide `defaults` setting — declaring it under `tool`, `profile`, or `server-defaults` is rejected at load time.

<a id="pathless"></a>

### Tools with no path argument

A calculation or echo tool can inherit runtime filesystem grants and unexpectedly require a path argument.
Add a tool like this inside the file policy's `server` block:

```kdl
tool "echo" side_effect="read_only" {
    filesystem {
        allow none=#true
        require-path #false
    }
}
```

This allows path-free arguments such as `{"message":"hello"}` while rejecting supplied paths. `require-path #false` is valid only with an empty allowlist.
Network grants are inherited too, so review `tool.network` if moving this example into a policy with open network access.

### Constraining argument structure

To check argument types and required fields as well as paths, set `args_schema` on the tool.
Replace the existing `read_file` inside `server "files"` in the Linux example with this block. On Windows, substitute the corresponding `C:/mcp/data/...` path.

```kdl
tool "read_file" side_effect="read_only" args_schema="@schemas/read-file.json" {
    filesystem {
        allow "/srv/mcp-data/public/**" mode="read"
    }
}
```

Save the following as `schemas/read-file.json` in the policy's directory. Relative `@` paths are resolved against the directory of the policy being loaded.

```json
{
  "type": "object",
  "properties": {"path": {"type": "string"}},
  "required": ["path"],
  "additionalProperties": false
}
```

`args_schema` checks `params.arguments`. MRTR `inputResponses` is a separate input: the default `auto` mode denies it on tools with a schema, `side_effect`, or effective permission constraints. See the [protocol reference](guide.md#mcp-2026-07-28--2025-11-25--mrtr-auditor) if your server needs MRTR.

## 6. Re-verify in a normal run and re-pin the difference

Remove `--dry-run` from the client's launch configuration, choose a separate log such as `enforced.jsonl`, and restart it. Policy edits take effect when the guard restarts.
Repeat the table in [step 3](#verification), checking successful execution of allowed operations and the JSON-RPC errors and `action="denied"` records for denied operations.

The OS can still reject startup or access after RPC checks pass. Inspect server stderr alongside the audit log; not every OS denial is recorded in JSONL.
Do not count runs with `MCP_WRIT_SKIP_SANDBOX` or the fallback `sandbox allow_degraded=#true` as verification of normal protection.

After changing a policy, restart the guard and repeat both successful and denied cases.
When updating a server, regenerate into a separate file and review changes to tools, schemas, hashes, and permissions before adopting them — re-pin `tools-list-hash` and the workload hashes (`binary-hash` / `entrypoint-hash`) from that reviewed difference. Do not resolve a hash mismatch merely by removing the pin: a `binary-hash` / `entrypoint-hash` / `tools-list-hash` mismatch means the file or advertised tool set on this host is no longer the one you reviewed.

For additional syntax such as inheritance and file splitting, see [policy.example.kdl](../policy.example.kdl) and the [policy reference](guide.md#5-policy-reference).
