#!/usr/bin/env python3
"""Synthetic MCP stdio server for Warden self-test evidence.

Allowed tool `read_file` opens `arguments.path` with no extra checks so the
OS (Landlock) is the denier. Tool failures are MCP `result.isError=true`,
not JSON-RPC protocol errors. No RCE canaries.
"""
from __future__ import annotations

import errno
import json
import sys


def reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def open_path(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            data = fh.read(64)
        head = data.decode("utf-8", "replace")
        return {"ok": True, "n": len(data), "head": head}
    except OSError as e:
        err = e.errno
        name = errno_name(err)
        return {
            "ok": False,
            "errno": err,
            "error": name,
            "message": f"open failed: {name} (os error {err})",
        }


def errno_name(err: int) -> str:
    if err == getattr(errno, "EACCES", 13):
        return "EACCES"
    if err == getattr(errno, "EPERM", 1):
        return "EPERM"
    return f"errno_{err}"


def call_tool_result(outcome: dict) -> dict:
    if outcome.get("ok"):
        return {
            "content": [{"type": "text", "text": outcome["head"]}],
            "structuredContent": {
                "ok": True,
                "n": outcome["n"],
                "head": outcome["head"],
            },
        }
    return {
        "isError": True,
        "content": [{"type": "text", "text": outcome["message"]}],
    }


def main() -> None:
    initialized = False
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        mid = msg.get("id")

        if method == "initialize":
            initialized = True
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "open-path-fixture", "version": "1.0.0"},
                    },
                }
            )
            continue

        if method == "notifications/initialized":
            continue

        if method == "tools/list":
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "read_file",
                                "description": "Open a path and return a short prefix",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                },
                            }
                        ]
                    },
                }
            )
            continue

        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            path = args.get("path")
            if name != "read_file" or not isinstance(path, str):
                reply(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32602, "message": "expected read_file.path"},
                    }
                )
                continue
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": call_tool_result(open_path(path)),
                }
            )
            continue

        if mid is not None:
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )

    if not initialized:
        return


if __name__ == "__main__":
    main()
