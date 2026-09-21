#!/bin/sh
# Fetch the pinned real MCP servers used by tests/real_servers_e2e.rs.
# No arguments. Idempotent: skips each runtime that is already installed.
set -eu
cd "$(dirname "$0")"

# Node: package-lock.json is committed; npm ci reproduces it exactly.
if [ -d node/node_modules ]; then
    echo "setup: node already installed (node/node_modules present)"
else
    (cd node && npm ci --ignore-scripts)
    echo "setup: node installed"
fi

# Python: requirements.txt pins every artifact by sha256. A venv counts as
# installed only when the marker written after a successful pip install is
# present — a leftover from an interrupted run is removed and recreated.
if [ -f python/.venv/.install-complete ]; then
    echo "setup: python already installed (python/.venv present)"
else
    rm -rf python/.venv
    python3 -m venv python/.venv
    python/.venv/bin/pip install --require-hashes -r python/requirements.txt
    touch python/.venv/.install-complete
    echo "setup: python installed"
fi

echo "setup: done"
