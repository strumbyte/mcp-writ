#!/usr/bin/env python3
"""MCP 2025-11-25 rmcp-like fixture: exit on pre-initialize traffic.

Each process start appends to MCP_WRIT_TEST_MARKER (when set):
  start
  die_preinit   — first frame was not initialize; process exits
  init_ok       — initialize accepted on this process
"""
from __future__ import annotations

import json
import os
import sys


def log_event(event: str) -> None:
    path = os.environ.get("MCP_WRIT_TEST_MARKER")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(event + "\n")


def reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    log_event("start")
    first = True
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

        if first:
            first = False
            if method != "initialize":
                log_event("die_preinit")
                sys.exit(2)

        if method == "initialize":
            initialized = True
            log_event("init_ok")
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "dies-on-preinit", "version": "1.0.0"},
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
                        "error": {"code": -32600, "message": "not initialized"},
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
                                "name": "echo",
                                "description": "Echo text",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string"}},
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
