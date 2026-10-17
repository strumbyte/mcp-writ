#!/usr/bin/env python3
"""Capture `tools/list` snapshots from public MCP servers into the manifest
regression corpus at `tests/fixtures/manifest_corpus/`.

For each server in the REGISTRY below the script launches the real package
over stdio, performs the MCP `2025-11-25` handshake, issues `tools/list`,
and writes the JSON-RPC response — pretty-printed — to
`<name>.tools-list.json`. `provenance.json` is refreshed with the resolved
package, pinned version, license, launch argv, and capture date.

Sources:
- `pinned`: the vendored installs under `tests/fixtures/real_servers/`
  (populate them first with `tests/fixtures/real_servers/setup.sh` /
  `setup.ps1`). Versions come from that tree's lock data.
- `npm`: ephemeral `npm install` of the pinned version into a scratch dir
  under `target/manifest-corpus/` (kept on the data drive per
  `AGENTS.md` disk hygiene; removed after the run).
- `pypi`: ephemeral venv + `pip install` of the pinned version, same root.

Requirements: Python 3.10+, `node` + `npm` on PATH for npm sources,
`python3 -m venv` for pypi sources. No third-party Python packages.
Under WSL, Windows `node.exe`/`python.exe` fixtures run through interop
and path arguments are translated via `wslpath`.

Usage:
    python3 scripts/capture-manifest-corpus.py            # capture all
    python3 scripts/capture-manifest-corpus.py fetch git  # named only
"""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "tests" / "fixtures" / "manifest_corpus"
REAL_SERVERS = REPO_ROOT / "tests" / "fixtures" / "real_servers"
SCRATCH_ROOT = REPO_ROOT / "target" / "manifest-corpus"

PROTOCOL_VERSION = "2025-11-25"
CLIENT_INFO = {"name": "mcp-writ-manifest-corpus", "version": "0.1.0"}
# Slow starters (browser-tool servers load big dependency graphs) get this
# whole budget; capture fails rather than writing a partial file.
CAPTURE_TIMEOUT_SECS = 180


@dataclass
class ServerSpec:
    name: str           # fixture file stem
    package: str        # npm or PyPI package name
    version: str        # pinned version
    license: str        # SPDX identifier of the upstream project
    upstream: str       # source repository URL
    source: str         # "pinned" | "npm" | "pypi"
    note: str = ""
    args: list = field(default_factory=list)


SERVERS = [
    # Official reference servers — github.com/modelcontextprotocol/servers (MIT).
    ServerSpec(
        name="filesystem",
        package="@modelcontextprotocol/server-filesystem",
        version="2026.8.31",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="pinned",
        # One allowed dir is required at startup; tools/list does not touch it.
        args=["."],
    ),
    ServerSpec(
        name="memory",
        package="@modelcontextprotocol/server-memory",
        version="2026.8.31",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="pinned",
    ),
    ServerSpec(
        name="time",
        package="mcp-server-time",
        version="2026.8.18",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="pinned",
        # The server embeds the detected local zone in its tool schemas;
        # pin it so the snapshot is host-independent.
        args=["--local-timezone", "UTC"],
    ),
    ServerSpec(
        name="git",
        package="mcp-server-git",
        version="2026.8.18",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="pinned",
        args=["--repository", "."],
    ),
    ServerSpec(
        name="fetch",
        package="mcp-server-fetch",
        version="2026.10.10",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="pypi",
        # 2026.8.18 carried no annotations; 2026.10.10 is the first
        # release that advertises the F-07 combination.
        note="F-07 regression case: readOnlyHint + url key + openWorldHint.",
    ),
    ServerSpec(
        name="everything",
        package="@modelcontextprotocol/server-everything",
        version="2026.8.31",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="npm",
    ),
    ServerSpec(
        name="sequential-thinking",
        package="@modelcontextprotocol/server-sequential-thinking",
        version="2026.8.31",
        license="MIT",
        upstream="https://github.com/modelcontextprotocol/servers",
        source="npm",
    ),
    # Widely used third-party servers.
    ServerSpec(
        name="playwright",
        package="@playwright/mcp",
        version="0.0.83",
        license="Apache-2.0",
        upstream="https://github.com/microsoft/playwright-mcp",
        source="npm",
    ),
    ServerSpec(
        name="chrome-devtools",
        package="chrome-devtools-mcp",
        version="1.11.0",
        license="Apache-2.0",
        upstream="https://github.com/ChromeDevTools/chrome-devtools-mcp",
        source="npm",
    ),
]


def running_wsl() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False


WSL = running_wsl()


def is_windows_binary(path: str) -> bool:
    """True when `path` execs through WSL/Windows interop (.exe)."""
    return WSL and path.lower().endswith(".exe")


def child_path(p: Path, windows: bool) -> str:
    """Spell `p` for the child's address space: Windows binaries get a
    `D:\\...` spelling, native processes keep the POSIX spelling."""
    if not windows:
        return str(p)
    out = subprocess.run(
        ["wslpath", "-w", str(p)], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def which_any(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def node_bin() -> str:
    p = which_any("node", "node.exe")
    if not p:
        raise SystemExit("node not found on PATH (needed for npm/pinned servers)")
    return p


def npm_install(prefix: Path, spec: str):
    npm = which_any("npm", "npm.cmd", "npm.exe")
    if not npm:
        raise SystemExit("npm not found on PATH")
    # A `npm` resolved under a drvfs mount (or a `.cmd`/`.exe` shim) is
    # Windows code reached through WSL interop: hand it a Windows prefix
    # path. Native `npm`/`npm.cmd` on Windows already takes native paths.
    windows_npm = WSL and (
        "/mnt/" in npm or npm.lower().endswith((".cmd", ".exe"))
    )
    prefix_arg = child_path(prefix, windows=windows_npm)
    args = ["install", "--prefix", prefix_arg, "--ignore-scripts", "--no-save", spec]
    if npm.lower().endswith(".cmd"):
        # Batch shims need a Windows shell — `cmd.exe` resolves through
        # WSL interop as well, and wants a Windows-spelled npm path.
        npm_arg = child_path(Path(npm), windows=WSL)
        cmd = ["cmd.exe" if WSL else "cmd", "/c", npm_arg, *args]
    else:
        cmd = [npm, *args]
    subprocess.run(cmd, check=True)


def pypi_install(prefix: Path, spec: str) -> Path:
    """Install `spec` into an isolated venv under `prefix`; return its python.

    Tries the running interpreter's `venv` module first. Minimal WSL
    distros often lack ensurepip, so under WSL a Windows `py` launcher is
    the fallback — it builds a Windows venv (Windows paths via wslpath)
    whose `Scripts/python.exe` runs through interop.
    """
    venv = prefix / "venv"
    attempts: list[tuple[list, Path]] = []
    # Interpreters without ensurepip cannot bootstrap a venv — skip them
    # quietly rather than letting `venv` print its install instructions.
    has_ensurepip = (
        subprocess.run(
            [sys.executable, "-c", "import ensurepip"],
            capture_output=True,
        ).returncode
        == 0
    )
    if has_ensurepip:
        if os.name == "nt":
            attempts.append(([sys.executable, "-m", "venv", str(venv)], venv / "Scripts" / "python.exe"))
        else:
            attempts.append(([sys.executable, "-m", "venv", str(venv)], venv / "bin" / "python"))
    if WSL:
        py = which_any("py.exe", "py")
        if py:
            attempts.append(
                ([py, "-3", "-m", "venv", child_path(venv, True)], venv / "Scripts" / "python.exe")
            )
    for cmd, python in attempts:
        if subprocess.run(cmd).returncode == 0 and python.is_file():
            break
    else:
        raise SystemExit("could not create a venv for pypi capture (no ensurepip / no py launcher)")
    subprocess.run([str(python), "-m", "pip", "install", "--quiet", spec], check=True)
    return python


def pinned_node_entry(spec: ServerSpec) -> Path:
    return (
        REAL_SERVERS
        / "node" / "node_modules" / spec.package / "dist" / "index.js"
    )


def pinned_python() -> Path:
    venv = REAL_SERVERS / "python" / ".venv"
    for cand in (venv / "bin" / "python", venv / "Scripts" / "python.exe"):
        if cand.is_file():
            return cand
    raise SystemExit(
        "real_servers python venv missing: run tests/fixtures/real_servers/setup.* first"
    )


def package_bin(package_root: Path) -> Path:
    meta = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    bin_field = meta.get("bin")
    if isinstance(bin_field, str):
        rel = bin_field
    elif isinstance(bin_field, dict) and bin_field:
        # Chrome DevTools and friends declare several bins; the *-mcp /
        # package-named entry is the server — pick the longest (most
        # specific) name for stability, first declared on ties.
        if len(bin_field) == 1:
            rel = next(iter(bin_field.values()))
        else:
            named = [k for k in bin_field if k.endswith("-mcp")]
            rel = bin_field[named[0]] if named else bin_field[sorted(bin_field)[-1]]
    else:
        rel = meta.get("main") or "dist/index.js"
    return package_root / rel


def argv_for(spec: ServerSpec, scratch: Path) -> tuple[list, list]:
    """(resolved argv, logical argv). The resolved argv is spawned; the
    logical argv is recorded in provenance — machine-local paths would
    churn the committed file on every recapture."""
    if spec.source == "pinned" and spec.package.startswith("@"):
        entry = pinned_node_entry(spec)
        if not entry.is_file():
            raise SystemExit(
                f"pinned fixture missing: {entry} — "
                "run tests/fixtures/real_servers/setup.* first"
            )
        node = node_bin()
        rel = entry.relative_to(REPO_ROOT).as_posix()
        return [node, child_path(entry, is_windows_binary(node)), *spec.args], [
            "node", rel, *spec.args,
        ]
    if spec.source == "pinned":
        module = {  # package name → importable module
            "mcp-server-time": "mcp_server_time",
            "mcp-server-git": "mcp_server_git",
        }[spec.package]
        return [str(pinned_python()), "-m", module, *spec.args], [
            "python", "-m", module, *spec.args,
        ]
    if spec.source == "npm":
        install_root = scratch / "npm" / spec.name
        npm_install(install_root, f"{spec.package}@{spec.version}")
        pkg_root = install_root / "node_modules" / spec.package
        node = node_bin()
        entry = package_bin(pkg_root)
        rel = entry.relative_to(pkg_root).as_posix()
        return [node, child_path(entry, is_windows_binary(node)), *spec.args], [
            "node", f"{spec.package}@{spec.version}/{rel}", *spec.args,
        ]
    if spec.source == "pypi":
        py = pypi_install(scratch / "pypi" / spec.name, f"{spec.package}=={spec.version}")
        module = spec.package.replace("-", "_")
        return [str(py), "-m", module, *spec.args], [
            "python", "-m", module, *spec.args,
        ]
    raise SystemExit(f"unknown source {spec.source!r} for {spec.name}")


class StdioJsonRpc:
    """Line-delimited JSON-RPC over the child's stdin/stdout, with a
    reader thread so a chatty or stalled server cannot wedge the capture."""

    def __init__(self, argv, cwd):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.lines = queue.Queue()
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()
        # stderr must be drained while the server runs — a chatty server
        # otherwise blocks once the pipe buffer fills. Bounded deque: only
        # the tail is wanted for error reporting.
        self._stderr_lock = threading.Lock()
        self.stderr_tail = deque(maxlen=64)
        self.err_thread = threading.Thread(target=self._pump_stderr, daemon=True)
        self.err_thread.start()

    def _pump(self):
        try:
            for line in self.proc.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def _pump_stderr(self):
        try:
            for line in self.proc.stderr:
                with self._stderr_lock:
                    self.stderr_tail.append(line)
        except Exception:
            pass

    def _stderr_text(self) -> str:
        # Bounded wait so the pump can flush a dying server's last lines;
        # a grandchild still holding the pipe must not hang this read.
        self.err_thread.join(timeout=2)
        with self._stderr_lock:
            return "".join(self.stderr_tail)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def request(self, req_id, method, params=None):
        self.send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        end = time.monotonic() + CAPTURE_TIMEOUT_SECS
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{method}: no response within {CAPTURE_TIMEOUT_SECS}s")
            line = self.lines.get(timeout=left)
            if line is None:
                raise RuntimeError(
                    f"{method}: server exited (code {self.proc.poll()}) "
                    f"stderr: {self._stderr_text()[-2000:]}"
                )
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # log chatter on stdout; not JSON-RPC
            if msg.get("id") == req_id:
                return msg

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def capture(spec: ServerSpec, scratch: Path):
    argv, logical_argv = argv_for(spec, scratch)
    rpc = StdioJsonRpc(argv, cwd=REPO_ROOT)
    try:
        init = rpc.request(
            1,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        if "error" in init:
            raise RuntimeError(f"initialize rejected: {init['error']}")
        rpc.notify("notifications/initialized")
        response = rpc.request(2, "tools/list")
        if "error" in response:
            raise RuntimeError(f"tools/list rejected: {response['error']}")
        return logical_argv, response
    finally:
        rpc.close()


def main():
    wanted = sys.argv[1:]
    specs = [s for s in SERVERS if not wanted or s.name in wanted]
    if not specs:
        raise SystemExit(f"no matching servers; known: {[s.name for s in SERVERS]}")
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    fetched = datetime.now(timezone.utc).date().isoformat()
    prov_path = CORPUS_DIR / "provenance.json"
    provenance = {"schema": "mcp-writ-manifest-corpus-v1", "servers": []}
    if prov_path.is_file():
        try:
            provenance = json.loads(prov_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    by_name = {s["name"]: s for s in provenance.get("servers", [])}

    scratch = Path(tempfile.mkdtemp(prefix="scratch-", dir=SCRATCH_ROOT))
    try:
        for spec in specs:
            print(f"[{spec.name}] {spec.package}@{spec.version} ({spec.source})", flush=True)
            argv, response = capture(spec, scratch)
            tools = response.get("result", {}).get("tools", [])
            if not isinstance(tools, list) or not tools:
                raise RuntimeError(f"{spec.name}: tools/list carried no tools")
            out = CORPUS_DIR / f"{spec.name}.tools-list.json"
            out.write_text(
                json.dumps(response, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            by_name[spec.name] = {
                "name": spec.name,
                "file": out.name,
                "package": spec.package,
                "version": spec.version,
                "license": spec.license,
                "upstream": spec.upstream,
                "source": spec.source,
                "fetched_at": fetched,
                "argv": argv,
                "tool_count": len(tools),
                **({"note": spec.note} if spec.note else {}),
            }
            print(f"  {len(tools)} tools -> {out.relative_to(REPO_ROOT)}", flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    provenance["captured_at_utc"] = fetched
    provenance["generator"] = "scripts/capture-manifest-corpus.py"
    provenance["servers"] = [by_name[s.name] for s in SERVERS if s.name in by_name]
    prov_path.write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"provenance -> {prov_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
