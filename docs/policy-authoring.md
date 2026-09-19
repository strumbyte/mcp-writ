# Writing a policy

[日本語](policy-authoring.ja.md) / [Command and policy reference](guide.md#5-policy-reference)

This guide takes an MCP server policy through draft generation, permission editing, dry-run checks, and a normal sandboxed run.
`generate-policy` can leave tool definitions and required runtime permissions incomplete. Saving its output does not mean the policy is ready to use.

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

## 2. Generate a draft and copy it for editing

Begin with static inspection, which does not execute the server. Replace the command and paths below with your actual server.

```sh
mcp-writ generate-policy --output policy.draft.kdl -- python /opt/mcp-server/server.py
```

For a native ELF, use `-- /opt/mcp-server/my-mcp-server`; for JavaScript, use `-- node /opt/mcp-server/server.js`.
Native inspection handles ELF files, not Windows `.exe` files.
Source inspection also depends on supported registration and handler patterns. If dynamic registration or a command such as `python -m` prevents source identification, fill in tools from their actual definitions.
`--project <dir>` adds hints from dependencies and project files; it does not guarantee complete tool detection or permissions.

To execute the server and retrieve tool definitions and schemas, write a separate draft:

```sh
mcp-writ generate-policy --live-discovery --output policy.discovered.kdl -- python /opt/mcp-server/server.py
```

`--live-discovery` restricts environment variables but does not run discovery inside an OS sandbox. Use a server you have decided to execute in a test environment.
If discovery fails because credentials or other environment variables are absent, you can also write the policy manually. Normal `run` inherits its parent's environment variables.

Copy the chosen draft to `policy.kdl` for editing:

```sh
cp policy.draft.kdl policy.kdl
```

In PowerShell, use `Copy-Item -LiteralPath policy.draft.kdl -Destination policy.kdl`.
Regenerate into a separate file later so that you do not overwrite the reviewed `policy.kdl`.

Check the draft for the following:

- If `server` / `tool` entries are absent, add the actual tools you intend to use. Tools absent from the policy are denied.
- If `filesystem` has no allowed paths, add runtime files and tool data paths.
- Review the reasons in `REVIEW` / `WARNING` comments. Unbound handlers or tools without sufficient evidence may have no `side_effect`.
- Review and retain `args_schema` and `tools-list-hash` obtained from live discovery. Do not invent a hash value.

`--self-test` is an optional diagnostic of a newly generated draft. It does not load an edited policy file for verification. Verify your edited policy in [step 5](#verification).

<a id="editing"></a>

## 3. Edit runtime permissions and tool permissions

For example, this kind of draft does not yet establish allowed read locations or the OS permissions needed to start the server:

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
| `defaults.syscalls` | Linux seccomp allowlist for the whole process |
| `defaults.network` | Shared network configuration; OS enforcement differs by platform |
| `tool` inside `server` | Allowed tools and the paths, hosts, and schemas accepted in their RPC arguments |

Windows grants OS file access from global settings. Linux also adds allowed tools' file permissions to Landlock.
Both are process-wide grants. The OS sandbox does not switch for each tool call. Declare shared runtime permissions explicitly, then narrow each tool's arguments to its intended scope.

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
For a native ELF, inspect syscall candidates with `mcp-writ inspect --format json /opt/mcp-server/my-mcp-server`. Static inspection cannot cover every execution path or dynamic library, so verify with a normal run.

A policy that allows an entire parent directory and tries to exclude a secret subdirectory with `deny` is rejected at load time because Landlock cannot express that restriction. List separate directories that may be accessed instead.

<a id="recipes"></a>

## 4. Adapt the policy to the workload

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
See the [reference](guide.md#field-reference) for OS and RPC network constraints.

Do not apply this `tool.network` example unchanged to a tool that calls a fixed API without receiving a URL/host argument: calls with no host are also denied. The Auditor cannot verify a destination absent from the arguments; consider the server implementation and network controls in its execution environment.

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

<a id="verification"></a>

## 5. Verify through an MCP client

Create test data: `hello.txt` inside the allowed directory and a harmless file outside that scope. Testing with real secret files is unnecessary.
The following starts the Linux read example. Create the audit log's parent directory somewhere writable by the user running the guard.

```sh
mcp-writ run --dry-run --policy /opt/mcp-config/policy.kdl --audit-log /opt/mcp-logs/dry-run.jsonl -- /opt/mcp-server/my-mcp-server
```

For the Windows example, use PowerShell:

```powershell
mcp-writ run --dry-run --policy C:/mcp/config/policy.windows.kdl --audit-log C:/mcp/logs/dry-run.jsonl -- C:/mcp/server/my-mcp-server.exe
```

Starting these commands in a terminal alone does not exercise tool checks. Configure an MCP client to launch the guard over stdio, obtain `tools/list`, and call the tools through that client.
Here is an example command and argument configuration. Adapt the surrounding configuration structure to your client.

```json
{
  "command": "mcp-writ",
  "args": [
    "run", "--dry-run",
    "--policy", "/opt/mcp-config/policy.kdl",
    "--audit-log", "/opt/mcp-logs/dry-run.jsonl",
    "--", "/opt/mcp-server/my-mcp-server"
  ]
}
```

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

On Windows, substitute the corresponding `C:/mcp/data/...` file paths. Passing API RPC checks and completing an authenticated network request are separate results to verify.

Inspect `event_type`, `action`, `target_tool`, and `details` in the audit log. This illustrative excerpt contains only the fields needed for diagnosis:

```json
{"event_type":"tool_call.denied","action":"observed","target_tool":"read_file","details":"path '...' not in tool fs allowed paths"}
```

`action="observed"` records a violation forwarded during dry-run. A returned tool result does not necessarily mean the policy allowed the call.
Use `details` to adjust the relevant tool, path, or host so that only intended operations pass.

### What to check in a normal run

Remove `--dry-run` from the client's launch configuration, choose a separate log such as `enforced.jsonl`, and restart it. Policy edits take effect when the guard restarts.
Repeat the table above, checking successful execution of allowed operations and the JSON-RPC errors and `action="denied"` records for denied operations.

The OS can still reject startup or access after RPC checks pass. Inspect server stderr alongside the audit log; not every OS denial is recorded in JSONL.
Do not count runs with `MCP_WRIT_SKIP_SANDBOX` or the fallback `sandbox allow_degraded=#true` as verification of normal protection.

<a id="troubleshooting"></a>

## 6. Find the setting behind a denial

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
| Manifest finding `CC-...` / tool definition hash mismatch | Changes in server descriptions, schemas, or versions. Broader filesystem grants do not fix these |

After changing a policy, restart the guard and repeat both successful and denied cases.
When updating a server, regenerate into a separate file and review changes to tools, schemas, hashes, and permissions before adopting them. Do not resolve a hash mismatch merely by removing `tools-list-hash`.

For additional syntax such as inheritance and file splitting, see [policy.example.kdl](../policy.example.kdl) and the [policy reference](guide.md#5-policy-reference).
