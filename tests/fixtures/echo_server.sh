#!/bin/sh
# Simple echo server for E2E testing.
# Reads lines from stdin, echoes them to stdout.
# Used as a mock MCP server that responds to JSON-RPC requests.

while IFS= read -r line; do
    printf '%s\n' "$line"
done
