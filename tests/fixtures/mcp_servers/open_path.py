#!/usr/bin/env python3
"""Synthetic MCP stdio server for path-resolution evidence.

Every tool performs a real filesystem operation and reports the identity of
the object it actually reached — never just a re-normalized copy of the
input string.

Tools:
  read_file   {path}           open read; head + handle identity
  create_file {path, content?} create_new write; created + parent identity
  ident       {path}           stat + lstat identity without open()
  kind        {path}           lstat file type only
  wait_file   {path, barrier}  wait for `barrier` to exist, then like read_file
  open_env    {env?}           open $env (default MCP_WRIT_FIXTURE_INTERNAL_PATH);
                               exercises an access the Auditor cannot see in args

Identity fields: dev/ino (st_dev/st_ino from fstat — on Windows these are
the volume serial and 64-bit file index), canonical (os.path.realpath),
kind. Tool failures are MCP result.isError=true, not JSON-RPC protocol
errors. No RCE canaries.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import sys
import time

DEFAULT_ENV_VAR = "MCP_WRIT_FIXTURE_INTERNAL_PATH"
WAIT_BARRIER_MAX_S = 15.0


def reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def kind_of(st_mode: int) -> str:
    if stat.S_ISLNK(st_mode):
        return "symlink"
    if stat.S_ISDIR(st_mode):
        return "dir"
    if stat.S_ISREG(st_mode):
        return "file"
    return "other"


def object_fields(path: str, st: os.stat_result) -> dict:
    try:
        canonical = os.path.realpath(path)
    except OSError:
        canonical = None
    return {
        "canonical": canonical,
        "kind": kind_of(st.st_mode),
        "dev": st.st_dev,
        "ino": st.st_ino,
    }


def errno_name(err: int | None) -> str:
    if err is None:
        return "os_error"
    return errno.errorcode.get(err, f"errno_{err}")


def error_result(exc: OSError) -> dict:
    err = exc.errno or 0
    name = errno_name(exc.errno)
    return {
        "isError": True,
        "content": [{"type": "text", "text": f"open failed: {name} (os error {err})"}],
        "structuredContent": {"ok": False, "errno": err, "error": name},
    }


def ok_result(head: str, structured: dict) -> dict:
    return {
        "content": [{"type": "text", "text": head}],
        "structuredContent": {"ok": True, **structured},
    }


def open_and_report(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            data = fh.read(64)
            st = os.fstat(fh.fileno())
    except OSError as e:
        return error_result(e)
    head = data.decode("utf-8", "replace")
    return ok_result(head, {**object_fields(path, st), "n": len(data)})


def tool_create_file(path: str, content: str | None) -> dict:
    try:
        with open(path, "xb") as fh:
            fh.write((content if content is not None else "created\n").encode("utf-8"))
            st = os.fstat(fh.fileno())
    except OSError as e:
        return error_result(e)
    created = object_fields(path, st)
    parent = os.path.dirname(path) or "."
    try:
        pst = os.stat(parent)
        created["parent"] = object_fields(parent, pst)
    except OSError:
        created["parent"] = {"canonical": None}
    return ok_result("created", created)


def tool_ident(path: str) -> dict:
    try:
        lst = os.lstat(path)
    except OSError as e:
        return error_result(e)
    try:
        st = os.stat(path)
        stat_fields = object_fields(path, st)
    except OSError:
        stat_fields = None
    return ok_result(
        "ident",
        {"lstat": object_fields(path, lst), "stat": stat_fields},
    )


def tool_kind(path: str) -> dict:
    try:
        st = os.lstat(path)
    except OSError as e:
        return error_result(e)
    return ok_result(kind_of(st.st_mode), {"kind": kind_of(st.st_mode)})


def tool_wait_file(path: str, barrier: str) -> dict:
    deadline = time.monotonic() + WAIT_BARRIER_MAX_S
    while not os.path.exists(barrier):
        if time.monotonic() > deadline:
            return error_result(OSError(errno.ETIMEDOUT, "barrier wait timed out"))
        time.sleep(0.005)
    return open_and_report(path)


def tool_open_env(env_name: str) -> dict:
    path = os.environ.get(env_name)
    if path is None:
        return error_result(OSError(errno.ENOENT, f"env var {env_name} not set"))
    result = open_and_report(path)
    sc = result.get("structuredContent")
    if sc is not None and sc.get("ok"):
        sc["env_path"] = path
    return result


TOOLS = [
    {
        "name": "read_file",
        "description": "Open a path and report handle identity",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "create_file",
        "description": "Create a file and report created+parent identity",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "ident",
        "description": "Report stat/lstat identity without open",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "kind",
        "description": "Report lstat file type",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "wait_file",
        "description": "Wait for barrier file then open path",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "barrier": {"type": "string"}},
            "required": ["path", "barrier"],
        },
    },
    {
        "name": "open_env",
        "description": "Open path from an env var (server-internal access)",
        "inputSchema": {
            "type": "object",
            "properties": {"env": {"type": "string"}},
        },
    },
]


def dispatch(msg: dict) -> dict | None:
    method = msg.get("method")
    mid = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "open-path-fixture", "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        result: dict | None = None
        if name == "read_file" and isinstance(args.get("path"), str):
            result = open_and_report(args["path"])
        elif name == "create_file" and isinstance(args.get("path"), str):
            result = tool_create_file(args["path"], args.get("content"))
        elif name == "ident" and isinstance(args.get("path"), str):
            result = tool_ident(args["path"])
        elif name == "kind" and isinstance(args.get("path"), str):
            result = tool_kind(args["path"])
        elif name == "wait_file" and isinstance(args.get("path"), str) and isinstance(
            args.get("barrier"), str
        ):
            result = tool_wait_file(args["path"], args["barrier"])
        elif name == "open_env":
            result = tool_open_env(
                args.get("env") if isinstance(args.get("env"), str) else DEFAULT_ENV_VAR
            )
        if result is not None:
            return {"jsonrpc": "2.0", "id": mid, "result": result}
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "error": {"code": -32602, "message": "unknown or malformed tool call"},
        }

    if mid is not None:
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        out = dispatch(msg)
        if out is not None:
            reply(out)


if __name__ == "__main__":
    main()
