#!/bin/sh
# check-server — run a real MCP server through mcp-writ and verify the
# handshake and (optionally) one tools/call survive the policy layers.
#
# Usage:
#   check-server --policy <kdl> [--audit-log <path>] [--call <json params>]
#                [--mcp-writ <path>] -- <server command...>
#
# Stages:
#   0. dry-run protocol probe: server/discover selects the request sequence
#   1. dry-run (Auditor only): negotiated-generation handshake + tools/list
#      (2025-11-25: initialize + notifications/initialized; 2026-07-28:
#      server/discover + per-request _meta, no initialize)
#   2. sandboxed: the same exchange under the OS sandbox
#   3. sandboxed: one tools/call when --call is given
#
# Each expected response must contain "result" and must not contain "error";
# a call response must not contain "isError":true. Fails non-zero otherwise.
set -eu

META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"check-server","version":"0"}}'
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check-server","version":"0"}}}'
NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST25='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
DISCOV="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{$META}}"
LIST26="{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{$META}}"

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

# judge <label> <expected response ids> <raw output> [call]
# Keeps lines that carry "jsonrpc"; each must hold a top-level "result"
# member and no top-level "error", and every expected request id must
# appear on a client-bound response. A '"error"' string inside a result
# payload must not count — python3 parses the lines when available; the
# grep fallback at least requires the member shape (`"error":` is always
# an object per JSON-RPC).
judge() {
    label=$1
    want_ids=$2
    out=$3
    mode=${4:-}
    resp=$(printf '%s\n' "$out" | grep '"jsonrpc"' || true)
    printf '%s\n' "$resp"
    if command -v python3 >/dev/null 2>&1; then
        # prints: <lines> <with-error> <without-result> <isError-true> <missing-ids>
        set -- $(printf '%s\n' "$resp" | python3 -c '
import json, sys
want = set(sys.argv[1:])
seen = set()
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
    # Only client-bound responses count: notifications and server-initiated
    # requests carry "method" (a request may carry "id" too).
    if "method" in obj or "id" not in obj:
        continue
    n += 1
    bad += "error" in obj
    noresult += "result" not in obj
    seen.add(str(obj.get("id")))
    r = obj.get("result")
    iserr += isinstance(r, dict) and r.get("isError") is True
missing = sum(1 for w in want if w not in seen)
print(n, bad, noresult, int(iserr), missing)
' $want_ids || echo "0 0 0 0 0")
        n=$1 bad=$2 noresult=$3 iserr=$4 missing=$5
    else
        # Same response filter as the python path: keep lines carrying an
        # "id" and no "method" so notifications and server-initiated
        # requests are not counted as responses.
        responly=$(printf '%s\n' "$resp" | grep '"id"[[:space:]]*:' | grep -v '"method"[[:space:]]*:' || true)
        n=$(printf '%s\n' "$responly" | grep -c '"jsonrpc"' || true)
        bad=$(printf '%s\n' "$responly" | grep -c '"error"[[:space:]]*:[[:space:]]*{' || true)
        noresult=$(printf '%s\n' "$responly" | grep -cv '"result"[[:space:]]*:' || true)
        iserr=0
        if [ "$mode" = "call" ]; then
            iserr=$(printf '%s\n' "$responly" | grep -c '"isError"[[:space:]]*:[[:space:]]*true' || true)
        fi
        missing=0
        for id in $want_ids; do
            # The id must be followed by a non-digit so `id`:1 cannot match
            # inside `"id":12`.
            if ! printf '%s\n' "$responly" | grep -q "\"id\"[[:space:]]*:[[:space:]]*$id\([^0-9]\|$\)"; then
                missing=$((missing + 1))
            fi
        done
    fi
    if [ "$n" -lt 1 ]; then
        echo "check-server: FAIL — $label: no JSON-RPC response" >&2
        return 1
    fi
    if [ "$missing" -gt 0 ]; then
        echo "check-server: FAIL — $label: missing response id(s) among: $want_ids" >&2
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

# A 2026-07-28 server endorses the revision via result.supportedVersions on
# server/discover, or via error.data.supported on a -32022 rejection. Anything
# else — including a plain method-not-found — falls back to the 2025-11-25
# initialize handshake.
echo "== stage 0: protocol probe (dry-run) =="
printf '%s\n' "$DISCOV" >"$REQFILE"
# A guard that exits non-zero during the probe must not kill the script:
# the collected output drives generation detection (empty → 2025-11-25
# fallback), and the numbered stages then report the failure with the
# audit-log dump instead of dying silently here.
probe_out=$(run_stage --dry-run "$REQFILE" "$@") || true
printf '%s\n' "$probe_out" | grep '"jsonrpc"' || true
generation=2025-11-25
if printf '%s\n' "$probe_out" | grep '"jsonrpc"' | grep '"supported' | grep -q '"2026-07-28"'; then
    generation=2026-07-28
fi
echo "check-server: negotiated generation: $generation"

if [ "$generation" = "2026-07-28" ]; then
    printf '%s\n%s\n' "$DISCOV" "$LIST26" >"$REQFILE"
    call_head="$DISCOV"
else
    printf '%s\n%s\n%s\n' "$INIT" "$NOTIF" "$LIST25" >"$REQFILE"
    call_head="$INIT
$NOTIF"
fi

echo "== stage 1: dry-run =="
if ! judge "stage 1 (dry-run)" "1 2" "$(run_stage --dry-run "$REQFILE" "$@")"; then
    fail=1
fi

echo "== stage 2: sandboxed =="
if ! judge "stage 2 (sandboxed)" "1 2" "$(run_stage "" "$REQFILE" "$@")"; then
    fail=1
fi

if [ -n "$CALL" ]; then
    call_params=$CALL
    if [ "$generation" = "2026-07-28" ]; then
        # Fold the per-request _meta into the params object.
        call_params=$(printf '%s' "$CALL" | sed 's|}[[:space:]]*$|,'"$META"'}|')
    fi
    printf '%s\n%s\n' "$call_head" "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":$call_params}" >"$REQFILE"
    echo "== stage 3: tools/call (sandboxed) =="
    if ! judge "stage 3 (tools/call)" "1 3" "$(run_stage "" "$REQFILE" "$@")" call; then
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
