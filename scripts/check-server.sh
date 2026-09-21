#!/bin/sh
# check-server — run a real MCP server through mcp-writ and verify the
# handshake and (optionally) one tools/call survive the policy layers.
#
# Usage:
#   check-server --policy <kdl> [--audit-log <path>] [--call <json params>]
#                [--mcp-writ <path>] -- <server command...>
#
# Stages:
#   1. dry-run (Auditor only): initialize + notifications/initialized + tools/list
#   2. sandboxed: the same exchange under the OS sandbox
#   3. sandboxed: one tools/call when --call is given
#
# Each expected response must contain "result" and must not contain "error";
# a call response must not contain "isError":true. Fails non-zero otherwise.
set -eu

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check-server","version":"0"}}}'
NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

usage() {
    echo "usage: check-server --policy <kdl> [--audit-log <path>] [--call <json>] [--mcp-writ <path>] -- <server command...>" >&2
    exit 2
}

POLICY=""
AUDIT_LOG=""
CALL=""
MCP_WRIT="mcp-writ"

while [ $# -gt 0 ]; do
    case "$1" in
        --policy) POLICY=$2; shift 2 ;;
        --audit-log) AUDIT_LOG=$2; shift 2 ;;
        --call) CALL=$2; shift 2 ;;
        --mcp-writ) MCP_WRIT=$2; shift 2 ;;
        --) shift; break ;;
        *) usage ;;
    esac
done

[ -n "$POLICY" ] || usage
[ $# -gt 0 ] || usage
command -v "$MCP_WRIT" >/dev/null 2>&1 || {
    echo "check-server: FAIL — mcp-writ not found: $MCP_WRIT" >&2
    exit 1
}

# A relative default works for both POSIX-native and WSL-interop (Win32)
# mcp-writ binaries: the child resolves it against the working directory.
if [ -z "$AUDIT_LOG" ]; then
    AUDIT_LOG="check-server-audit-$$.jsonl"
fi

# run_stage <extra run flag> <request lines file> <server command...>
# Prints the guard's stdout response lines on stdout.
run_stage() {
    flag=$1
    reqs=$2
    shift 2
    # Hold stdin open briefly after the last request so in-flight responses
    # are relayed before the guard shuts down on EOF.
    if [ -n "$flag" ]; then
        { cat "$reqs"; sleep 3; } |
            "$MCP_WRIT" run --transport stdio --policy "$POLICY" --audit-log "$AUDIT_LOG" "$flag" -- "$@"
    else
        { cat "$reqs"; sleep 3; } |
            "$MCP_WRIT" run --transport stdio --policy "$POLICY" --audit-log "$AUDIT_LOG" -- "$@"
    fi
}

fail=0

# judge <label> <raw output> [call]
# Keeps lines that carry "jsonrpc"; each must hold a top-level "result"
# member and no top-level "error". A '"error"' string inside a result
# payload must not count — python3 parses the lines when available; the
# grep fallback at least requires the member shape (`"error":` is always
# an object per JSON-RPC).
judge() {
    label=$1
    out=$2
    mode=${3:-}
    resp=$(printf '%s\n' "$out" | grep '"jsonrpc"' || true)
    printf '%s\n' "$resp"
    if command -v python3 >/dev/null 2>&1; then
        # prints: <lines> <with-error> <without-result> <isError-true>
        set -- $(printf '%s\n' "$resp" | python3 -c '
import json, sys
n = bad = noresult = iserr = 0
for line in sys.stdin:
    if "\"jsonrpc\"" not in line:
        continue
    try:
        obj = json.loads(line)
    except ValueError:
        obj = None
    if not isinstance(obj, dict):
        # A "jsonrpc"-mentioning line that is not a JSON object counts as
        # a malformed response, not as absent.
        n += 1
        noresult += 1
        continue
    n += 1
    bad += "error" in obj
    noresult += "result" not in obj
    r = obj.get("result")
    iserr += isinstance(r, dict) and r.get("isError") is True
print(n, bad, noresult, int(iserr))
' || echo "0 0 0 0")
        n=$1 bad=$2 noresult=$3 iserr=$4
    else
        n=$(printf '%s\n' "$resp" | grep -c '"jsonrpc"' || true)
        bad=$(printf '%s\n' "$resp" | grep -c '"error"[[:space:]]*:[[:space:]]*{' || true)
        noresult=$(printf '%s\n' "$resp" | grep -cv '"result"[[:space:]]*:' || true)
        iserr=0
        if [ "$mode" = "call" ]; then
            iserr=$(printf '%s\n' "$resp" | grep -c '"isError"[[:space:]]*:[[:space:]]*true' || true)
        fi
    fi
    if [ "$n" -lt 1 ]; then
        echo "check-server: FAIL — $label: no JSON-RPC response" >&2
        return 1
    fi
    if [ "$bad" -gt 0 ]; then
        echo "check-server: FAIL — $label: response carries \"error\"" >&2
        return 1
    fi
    if [ "$noresult" -gt 0 ]; then
        echo "check-server: FAIL — $label: response missing \"result\"" >&2
        return 1
    fi
    if [ "$mode" = "call" ] && [ "$iserr" -gt 0 ]; then
        echo "check-server: FAIL — $label: tools/call result isError" >&2
        return 1
    fi
    return 0
}

REQFILE="$(mktemp "${TMPDIR:-/tmp}/check-server-req-XXXXXX")"
trap 'rm -f "$REQFILE"' EXIT

printf '%s\n%s\n%s\n' "$INIT" "$NOTIF" "$LIST" >"$REQFILE"

echo "== stage 1: dry-run =="
if ! judge "stage 1 (dry-run)" "$(run_stage --dry-run "$REQFILE" "$@" 2>/dev/null)"; then
    fail=1
fi

echo "== stage 2: sandboxed =="
if ! judge "stage 2 (sandboxed)" "$(run_stage "" "$REQFILE" "$@" 2>/dev/null)"; then
    fail=1
fi

if [ -n "$CALL" ]; then
    printf '%s\n%s\n%s\n' "$INIT" "$NOTIF" "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":$CALL}" >"$REQFILE"
    echo "== stage 3: tools/call (sandboxed) =="
    if ! judge "stage 3 (tools/call)" "$(run_stage "" "$REQFILE" "$@" 2>/dev/null)" call; then
        fail=1
    fi
fi

echo "== audit log (last 20 lines) =="
if [ -f "$AUDIT_LOG" ]; then
    tail -n 20 "$AUDIT_LOG"
else
    echo "(no audit log written)"
fi

if [ "$fail" -ne 0 ]; then
    echo "check-server: FAIL"
    exit 1
fi
echo "check-server: PASS"
