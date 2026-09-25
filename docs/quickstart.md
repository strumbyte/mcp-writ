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
# Resolve this host's node install and global package tree — `command -v
# node` may be a shim/symlink, so follow the link chain to the real
# binary's directory and prefix.
node_bin="$(command -v node)"
while [ -L "$node_bin" ]; do
    link="$(readlink "$node_bin")"
    case "$link" in
        /*) node_bin="$link" ;;
        *)  node_bin="$(dirname "$node_bin")/$link" ;;
    esac
done
node_dir="$(dirname "$node_bin")"
node_prefix="$(dirname "$node_dir")"
npm_root="$(npm root -g)"

cat > policy.kdl <<EOF
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "$node_dir" mode="read"                    // resolved node bin dir
        allow "$node_prefix" mode="read"               // resolved node prefix
        allow "$npm_root" mode="read"                  // global npm package tree
        allow "/usr/lib" mode="read"                   // shared libraries
        allow "/usr/bin" mode="read"                   // env, exec'd via the shim's shebang
        allow "/lib" mode="read"
        allow "/lib64" mode="read"
        allow "/proc" mode="read"                      // V8/libuv read /proc/self/*; `self` is a per-process symlink Landlock cannot scope below — it also exposes other processes' procfs info, so grant it only for a dedicated OS user in a validation example
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

The example gives the path-taking tools an empty allow-list
(`allow none=#true`), so a path-taking tool without a matching override
stays fail-closed until you add `allow` entries for your own data root
(`list_allowed_directories` takes no path and already works). Use
`--server <name>` when the policy declares multiple servers.

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

`generate-policy` and `run` both resolve a bare `mcp-server-filesystem`
name through `PATH`, following the npm shim to its `dist/index.js` target —
that file is what the launch binds. Launching the shim directly leaves the
`#!/usr/bin/env node`-selected `node` unpinned, which `generate-policy`
marks with a `// REVIEW:` comment; invoking the JavaScript file with `node`
— `node <prefix>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`
— pins the interpreter. Either way, the shim's shebang needs `node` on
`PATH` at launch.

## 4. Dry-run the guard

Dry-run disables the OS sandbox and forwards policy violations while logging
them as `observed`, so use test data:

```sh
mcp-writ run --dry-run --policy policy.kdl --audit-log ./audit.jsonl -- mcp-server-filesystem /srv/mcp-data
```

Point a client (or a JSON-RPC script) at this command: `read_file` under the
allowed root succeeds and is logged `tool_call.allowed`; a path outside it —
e.g. a test file like `/tmp/hello-denied.txt` — is forwarded but logged
`tool_call.denied` with `action="observed"`.

## 5. Sandboxed check

`check-server` probes the server's protocol generation (`server/discover`),
then replays the matching handshake + `tools/list` through the guard with the
OS sandbox on; `--call` adds one `tools/call` to the run:

```sh
scripts/check-server.sh --policy policy.kdl -- mcp-server-filesystem /srv/mcp-data

# create a marker file under the data root, then exercise an allowed call
scripts/check-server.sh --policy policy.kdl \
  --call '{"name":"read_file","arguments":{"path":"/srv/mcp-data/marker.txt"}}' \
  -- mcp-server-filesystem /srv/mcp-data
```

Expect every stage to pass and the audit log to show `hash.verified` with
details `tools-list-hash verified` — the `tools/list` pin check — plus
`tool_call.allowed` when `--call` is given. This policy carries no
launch-target hash (`binary-hash`/`entrypoint-hash`), so no launch-target
`hash.verified` entry appears. On a kernel exposing only Landlock
ABI V1 the sandboxed stage refuses to launch fail-closed unless the policy
sets `sandbox allow_degraded=#true` (see [Caveats](#caveats)). A denied call
comes back as a JSON-RPC error, which `check-server` counts as a stage
failure, so exercise denials in a dry-run or client session instead.

## 6. Windows

On Windows the npm shim is not a valid analysis input, and AppContainer breaks
Node's `fs.realpath` under this package's symlinked layout, so this
verification flow launches the server through `node` with the shipped
realpath stub preloaded. The stub is a test aid, not a deployment recipe:
replacing `fs.realpath` disables the server's own symlink-escape check, and
the policy below still grants OS-level reads beyond the data root (the node
prefix, the package tree, the checkout). Keep the stub to verification
environments. Whether a sandboxed deployment can run without the stub is
unverified: a package path without symlinks (e.g. a `dist/` tree copied to
a real directory) would let the server's own check inspect link targets
where `fs.realpath` resolves, but under AppContainer it returns EPERM for
every path — sandboxed startup without the stub has not been exercised
end-to-end, so it is not presented as a deployment shape yet.

The `policy.kdl` from step 2 grants Linux paths only — write a Windows
variant first. Forward slashes avoid KDL backslash escapes; `nodeDir`
resolves to the installed prefix (e.g. `C:/Program Files/nodejs`):

```powershell
$nodeDir = (Get-Command node).Source | Split-Path -Parent
$pkgDir = "$env:APPDATA\npm\node_modules" -replace '\\','/'
$workDir = $PWD.Path -replace '\\','/'
$policy = @"
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "$($nodeDir -replace '\\','/')" mode="read"  // node install dir
        allow "$pkgDir" mode="read"                        // server package tree
        allow "$workDir" mode="read"                       // checkout root: child cwd + realpath stub — reads the whole checkout
        allow "C:/mcp/data" mode="read"                    // data root
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" { filesystem { allow "C:/mcp/data/**" } }
}
"@
[IO.File]::WriteAllText("$PWD\policy.kdl", $policy)
```

The `$workDir` grant is deliberately broad: the spawned child's working
directory is the checkout (AppContainer refuses an ungranted cwd) and the
realpath stub lives under `tests/fixtures/real_servers/node`, so this
exposes the entire checkout to OS-level reads. To narrow it, copy
`win-realpath-stub.cjs` into a dedicated directory, run
`check-server.ps1` from that directory, and grant only it instead of
`$workDir`. Outside the checkout, invoke the script by its absolute
checkout path (`C:\path\to\mcp-writ\scripts\check-server.ps1`) and point
`--require` at the stub copy's absolute path. Keep `policy.kdl` in the
checkout and pass its absolute path via `-Policy` — `extends` resolves
relative to the policy file, so a policy moved into the dedicated
directory would also need the `examples/policies/` tree (including
`runtime/`) copied alongside it.

Then discover, dry-run, and check with the Windows launch form:

```powershell
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
mcp-writ run --dry-run --policy policy.kdl --audit-log .\audit.jsonl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
scripts\check-server.ps1 -Policy policy.kdl node --preserve-symlinks-main --preserve-symlinks --require (Resolve-Path tests\fixtures\real_servers\node\win-realpath-stub.cjs).Path "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
```

## Caveats

- Landlock/seccomp is a Linux-only requirement — sandboxed launch on Linux
  needs a Landlock/seccomp-capable kernel. The Windows sandbox path is
  separate: §6's AppContainer launch form and `check-server.ps1` cover it.
  On kernels exposing only Landlock ABI V1 (e.g. WSL2 on kernel 5.15) the
  sandbox applies partially; `sandbox allow_degraded=#true` permits startup
  in that state, but it is not proof of full protection.
- Review the generated draft's tool permissions, paths, network access, and
  syscalls before use — static analysis does not prove a policy is complete or
  safe. See the [policy authoring guide](policy-authoring.md).
- For containers, keep the Linux `mcp-secure-runner` binary beside the CLI in
  its `runners/` directory. See the [container guide](guide.md#6-container-wrapping-deep-dive).
