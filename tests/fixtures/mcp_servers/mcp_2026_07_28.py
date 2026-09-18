#!/usr/bin/env python3
"""MCP 2026-07-28 stdio fixture requiring per-request _meta.

Answers server/discover and tools/list. Rejects initialize and missing _meta.
Pass `--accept-version VERSION` (or set MCP_WRIT_TEST_ACCEPT_VERSION) to make
tools/list return -32022 with another advertised revision.
"""
from __future__ import annotations

import json
import os
import sys


META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"
SUPPORTED_VERSION = "2026-07-28"


def reply(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def protocol_version(msg: dict) -> str | None:
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    version = meta.get(META_VERSION)
    return version if isinstance(version, str) else None


def has_client_capabilities(msg: dict) -> bool:
    params = msg.get("params")
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return False
    return META_CAPS in meta


def tools_result(mid) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": mid,
        "result": {
            "resultType": "complete",
            "ttlMs": 3600000,
            "cacheScope": "private",
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file from disk",
                    "title": "Read File",
                    "icons": [{"src": "data:image/png;base64,AA=="}],
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                }
            ],
        },
    }


def accepted_version() -> str:
    if len(sys.argv) == 3 and sys.argv[1] == "--accept-version":
        return sys.argv[2]
    return os.environ.get("MCP_WRIT_TEST_ACCEPT_VERSION", SUPPORTED_VERSION)


def main() -> None:
    accept = accepted_version()

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
        version = protocol_version(msg)

        if method == "initialize":
            if mid is not None:
                reply(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {
                            "code": -32601,
                            "message": "MCP 2026-07-28 fixture does not implement initialize",
                        },
                    }
                )
            continue

        if version is None or not has_client_capabilities(msg):
            if mid is not None:
                reply(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {
                            "code": -32602,
                            "message": "missing required _meta",
                        },
                    }
                )
            continue

        if method == "server/discover":
            # Discover advertises the implemented revision. tools/list may still
            # return -32022 when a test configures a different accepted version.
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": [SUPPORTED_VERSION],
                        "capabilities": {"tools": {}},
                        "ttlMs": 0,
                        "cacheScope": "private",
                    },
                }
            )
            continue

        if version != accept:
            if mid is not None:
                reply(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {
                            "code": -32022,
                            "message": "Unsupported protocol version",
                            "data": {"supported": [accept], "requested": version},
                        },
                    }
                )
            continue

        if method == "tools/list":
            reply(tools_result(mid))
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
