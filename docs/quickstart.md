# Quick Start Walkthrough

An end-to-end run of the README Quick Start against the pinned
`@modelcontextprotocol/server-filesystem` `2026.8.31` server, including the
sandboxed check that the short version omits. Replace `/srv/mcp-data` with the
directory the server may reach, and run from a
[source checkout](https://github.com/strumbyte/mcp-writ) with Rust and Node.js
installed.

## 1. Install

```sh
cargo install --locked --path . --bin mcp-writ
npm install -g @modelcontextprotocol/server-filesystem@2026.8.31
```

## 2. Write a host policy

The [reviewed example](../examples/policies/filesystem.kdl) pins the server's
tool surface (`tools-list-hash`) and per-tool rules but deliberately carries no
host paths. Extend it in `policy.kdl` at the checkout root and add this host's
`defaults` — the interpreter's read paths, the data root, and the syscall list
(the example already inherits the observed Node list via `runtime/node.kdl`):

```sh
cat > policy.kdl <<'EOF'
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "/home/your-user/.local/node" mode="read"  // resolved node prefix
        allow "/usr/lib" mode="read"                   // shared libraries
        allow "/usr/bin" mode="read"                   // env, exec'd via the shim's shebang
        allow "/lib" mode="read"
        allow "/lib64" mode="read"
        allow "/etc" mode="read"
        allow "/proc" mode="read"
        allow "/dev" mode="read"
        allow "/dev/null" mode="write"                 // interpreters open it O_RDWR
        allow "/srv/mcp-data" mode="read"              // data root passed to the server
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" { filesystem { allow "/srv/mcp-data/**" } }
}
EOF
```

The example pins `<ALLOWED_ROOT>` placeholders on the path-taking tools, so a
path-taking tool without a matching override stays fail-closed until you
replace the placeholder with your own data root (`list_allowed_directories`
takes no path and already works). Use `--server <name>` when the policy
declares multiple servers.

## 3. Discover the tool surface

`generate-policy --live-discovery` launches the server in a restricted
environment, queries `tools/list`, and writes a standalone draft policy
carrying the discovered `tools-list-hash` — it does not read `policy.kdl`:

```sh
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- "$(command -v mcp-server-filesystem)" /srv/mcp-data
```

Compare the draft's `tools-list-hash` and `tool` blocks against the pinned
values in `examples/policies/filesystem.kdl`; a difference means the server's
tool surface changed and the policy needs re-review. The authoritative check
is step 5, where `run` records `hash.verified` in the audit log.

`generate-policy` opens the server argument as a file for analysis, so pass the
resolved path to the npm shim (a symlink to `dist/index.js`, as shown) or use
`node <prefix>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`.
A bare `mcp-server-filesystem` name is not resolved on `PATH` here and fails
with `Error reading binary`. `run` does resolve the bare name by itself, but
either way the shim's `#!/usr/bin/env node` shebang needs `node` on `PATH` at
launch.

## 4. Dry-run the guard

Dry-run disables the OS sandbox and forwards policy violations while logging
them as `observed`, so use test data:

```sh
mcp-writ run --dry-run --policy policy.kdl --audit-log ./audit.jsonl -- mcp-server-filesystem /srv/mcp-data
```

Point a client (or a JSON-RPC script) at this command: `read_file` under the
allowed root succeeds and is logged `tool_call.allowed`; a path outside it —
e.g. `~/.ssh/id_rsa` — is forwarded but logged `tool_call.denied` with
`action="observed"`.

## 5. Sandboxed check

`check-server` replays initialize + `tools/list` through the guard with the OS
sandbox on; `--call` adds one `tools/call` to the run:

```sh
scripts/check-server.sh --policy policy.kdl -- mcp-server-filesystem /srv/mcp-data

# create a marker file under the data root, then exercise an allowed call
scripts/check-server.sh --policy policy.kdl \
  --call '{"name":"read_file","arguments":{"path":"/srv/mcp-data/marker.txt"}}' \
  -- mcp-server-filesystem /srv/mcp-data
```

Expect every stage to pass and the audit log to show `hash.verified` — plus
`tool_call.allowed` when `--call` is given. On a kernel exposing only Landlock
ABI V1 the sandboxed stage refuses to launch fail-closed unless the policy
sets `sandbox allow_degraded=#true` (see [Caveats](#caveats)). A denied call
comes back as a JSON-RPC error, which `check-server` counts as a stage
failure, so exercise denials in a dry-run or client session instead.

## 6. Windows

On Windows the npm shim is not a valid analysis input, and AppContainer breaks
Node's `fs.realpath` under this package's symlinked layout. Launch the server
through `node` and preload the shipped realpath stub:

```powershell
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
mcp-writ run --dry-run --policy policy.kdl --audit-log .\audit.jsonl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
scripts\check-server.ps1 -Policy policy.kdl node --preserve-symlinks-main --preserve-symlinks --require tests\fixtures\real_servers\node\win-realpath-stub.cjs "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
```

## Caveats

- Sandboxed launch needs a Landlock/seccomp-capable Linux. On kernels exposing
  only Landlock ABI V1 (e.g. WSL2 on kernel 5.15) the sandbox applies
  partially; `sandbox allow_degraded=#true` permits startup in that state, but
  it is not proof of full protection.
- Review the generated draft's tool permissions, paths, network access, and
  syscalls before use — static analysis does not prove a policy is complete or
  safe. See the [policy authoring guide](policy-authoring.md).
- For containers, keep the Linux `mcp-secure-runner` binary beside the CLI in
  its `runners/` directory. See the [container guide](guide.md#6-container-wrapping-deep-dive).
