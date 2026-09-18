#!/usr/bin/env python3
"""MCP 2025-11-25 stdio fixture requiring initialize + initialized.

Does NOT exit on pre-initialize traffic: `server/discover` and other unknown
requests get a -32601 "Method not found" reply (pre-init `tools/list` gets
-32600) and the read loop keeps running. The fixture that dies on
pre-initialize traffic is `mcp_2025_11_25_preinit_exit.py` — that is the one
the Legislator sibling-probe test uses to prove the disposable
server/discover probe cannot kill the real child.
"""
from __future__ import annotations

import json
import sys


SUPPORTED_VERSION = "2025-11-25"


def reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    selected_version = (
        sys.argv[2]
        if len(sys.argv) == 3 and sys.argv[1] == "--protocol-version"
        else SUPPORTED_VERSION
    )
    initialized = False
    got_initialized_notif = False

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
                        "protocolVersion": selected_version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mcp-2025-11-25-fixture", "version": "1.0.0"},
                    },
                }
            )
            continue

        if method == "notifications/initialized":
            got_initialized_notif = True
            continue

        if method == "tools/list":
            if not initialized or not got_initialized_notif:
                reply(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {
                            "code": -32600,
                            "message": "MCP 2025-11-25 fixture requires initialize + initialized",
                        },
                    }
                )
                continue
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "read_file",
                                "description": "Read a file from disk",
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

        if mid is not None:
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()
