#!/usr/bin/env bash
# PR-17/25 Kata VM validation job. Run on a Linux host meeting the
# environment in docs/validation/kata.md: a docker engine with the
# `kata` runtime registered, /dev/kvm and /dev/vhost-vsock, matching
# host/guest architecture, and rustc. Produces an evidence bundle under
# .local/kata-validation/<utc>-<uuid>/ and exits non-zero when the
# environment, the tests, or the evidence is missing — an unexecuted or
# unevidenced run is never a pass.
set -u -o pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
stamp=$(date -u +%Y%m%d-%H%M%S)-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
run_dir="$repo/.local/kata-validation/$stamp"
# Session scratch dirs are bind-mounted into the guest via virtiofs —
# they must live on a filesystem the runtime can share (on WSL2, /mnt/*
# drvfs mounts cannot be re-exported, so the checkout's own tree is out).
work=$(mktemp -d "${TMPDIR:-/tmp}/mcp-writ-kata-XXXXXXXX")
evidence="$run_dir/evidence"
log="$run_dir/test-output.txt"
result_json="$run_dir/result.json"
mkdir -p "$work" "$evidence" || { echo "cannot create $run_dir" >&2; exit 1; }

result=failed
commit=unknown
started_utc=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
work_cleanup=skipped

jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

emit_result() {
    local hashes="$1"
    cat >"$result_json" <<EOF
{"vm_requested":true,"result":"$result","started_utc":"$started_utc","finished_utc":"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)","commit":"$commit","host":{"os":"$(jstr "$(uname -s)")","kernel":"$(jstr "$(uname -r)")","distro":"$(jstr "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")")","arch":"$(uname -m)"},"rustc":"$(jstr "$(rustc --version 2>/dev/null || echo unavailable)")","docker":{"server":"$(jstr "${docker_server:-unavailable}")","client":"$(jstr "${docker_client:-unavailable}")","ostype":"$(jstr "${docker_ostype:-unavailable}")","kata_runtime_registered":${kata_runtime:-false}},"images":{"base":"$(jstr "${image_base:-unavailable}")","probe_base":"$(jstr "${image_probe_base:-unavailable}")","probe_secure":"$(jstr "${image_probe_secure:-unavailable}")"},"guest_kernel":"$(jstr "${guest_kernel:-unmeasured}")","tests":{"passed":${tests_passed:-0},"failed":${tests_failed:-0},"ignored":${tests_ignored:-0}},"evidence":{"metrics":${metrics_count:-0},"lifecycle":${lifecycle_count:-0},"dir":"$evidence"},"work_cleanup":"$work_cleanup","error":"$(jstr "${error:-}")","source_hashes":[$hashes]}
EOF
}

fail() {
    error="$*"
    echo "validate-kata: $*" >&2
    emit_result "$(source_hashes)"
    rm -rf -- "$work" 2>/dev/null
    echo "Validation record: $run_dir" >&2
    exit 1
}

source_hashes() {
    (
        cd "$repo" || exit 0
        for f in tests/kata_vm_e2e.rs scripts/validate-kata.sh \
            src/container/backends/kata.rs src/bin/mcp-secure-runner.rs; do
            [ -f "$f" ] && sha256sum "$f"
        done
        find tests/fixtures/kata -type f -exec sha256sum {} + 2>/dev/null
    ) | awk '{printf "%s{\"path\":\"%s\",\"sha256\":\"%s\"}", (NR>1?",":""), $2, $1}'
}

# ── environment gate — fail closed before any test work ─────────────
docker_ostype=$(docker info --format '{{.OSType}}' 2>/dev/null) \
    || fail "docker engine is not reachable"
docker_server=$(docker info --format '{{.ServerVersion}}' 2>/dev/null)
docker_client=$(docker version --format '{{.Client.Version}}' 2>/dev/null)
[ "$docker_ostype" = "linux" ] || fail "docker OSType is '$docker_ostype', expected linux"
docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"kata"' \
    && kata_runtime=true || fail "the 'kata' runtime is not registered with dockerd"
[ -e /dev/kvm ] || fail "/dev/kvm is absent — no hardware virtualization"
[ -e /dev/vhost-vsock ] || fail "/dev/vhost-vsock is absent — kata cannot reach the guest"
rustc --version >/dev/null 2>&1 || fail "rustc is not on PATH (probe compile)"
commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)

# ── disk headroom (AGENTS.md): <40 GiB → cargo clean, then still fail ──
target_dir=$(cargo metadata --locked --no-deps --format-version 1 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
low_space=false
for d in "$target_dir" "$work"; do
    [ -n "$d" ] || continue
    avail=$(df -k --output=avail "$d" 2>/dev/null | tail -1 | tr -d ' ')
    [ -n "$avail" ] && [ "$avail" -lt 41943040 ] && low_space=true
done
if $low_space; then
    (cd "$repo" && cargo clean)
fi
for d in "$target_dir" "$work"; do
    [ -n "$d" ] || continue
    avail=$(df -k --output=avail "$d" 2>/dev/null | tail -1 | tr -d ' ')
    if [ -n "$avail" ] && [ "$avail" -lt 41943040 ]; then
        fail "$d has less than 40 GiB free after cargo clean"
    fi
done

# ── run the gated suite — the env vars make unexecuted legs fail ─────
export MCP_WRIT_REQUIRE_KATA_TESTS=1
export MCP_WRIT_KATA_TEST_ROOT="${MCP_WRIT_KATA_TEST_ROOT:-$work}"
export MCP_WRIT_KATA_EVIDENCE_DIR="$evidence"
export CARGO_INCREMENTAL=0

cd "$repo"
cargo test --locked --test kata_vm_e2e -- --nocapture 2>&1 | tee "$log"
test_code=${PIPESTATUS[0]}

read -r tests_passed tests_failed tests_ignored <<<"$(
    awk '/test result:/{
        for(i=1;i<=NF;i++){
            if($i=="passed;")p+=$(i-1); if($i=="failed;")f+=$(i-1); if($i=="ignored;")g+=$(i-1)
        }} END{print p+0, f+0, g+0}' "$log"
)"

if [ "$test_code" -ne 0 ] || [ "$tests_failed" -gt 0 ]; then
    fail "kata_vm_e2e failed: ${tests_passed:-0} passed, ${tests_failed:-0} failed (see $log)"
fi
if [ "${tests_passed:-0}" -lt 5 ] || [ "${tests_ignored:-0}" -gt 0 ]; then
    fail "expected all 5 kata tests executed, got passed=${tests_passed:-0} ignored=${tests_ignored:-0} — an unexecuted leg is not a pass"
fi

# ── evidence completeness — a pass without its record is not a pass ──
metrics_count=0
lifecycle_count=0
for m in "$evidence"/*/metrics.json; do
    [ -e "$m" ] || continue
    metrics_count=$((metrics_count + 1))
    d=$(dirname "$m")
    # product (run-image) sessions prove the VM boundary via the host
    # launch report + host identity; harness (docker --runtime kata)
    # sessions via the guest report. Both keep the audit log.
    if grep -q '"tier":"product"' "$m"; then
        for req in host-identity.json report/host-launch-report.json logs/audit.jsonl; do
            [ -f "$d/$req" ] || fail "evidence missing: $d/$req"
        done
    else
        for req in report/report.json logs/audit.jsonl; do
            [ -f "$d/$req" ] || fail "evidence missing: $d/$req"
        done
    fi
done
for l in "$evidence"/*/lifecycle.json; do
    [ -e "$l" ] || continue
    lifecycle_count=$((lifecycle_count + 1))
    d=$(dirname "$l")
    ls "$d"/report/*.json >/dev/null 2>&1 \
        || fail "evidence missing: $d/report/*.json"
done
[ "$metrics_count" -eq 2 ] || fail "expected 2 session metrics records, got $metrics_count"
[ "$lifecycle_count" -eq 3 ] || fail "expected 3 lifecycle records, got $lifecycle_count"

# ── image + guest versions for the record ────────────────────────────
image_base=$(grep -o 'ubuntu@sha256:[a-f0-9]*' tests/kata_vm_e2e.rs | head -1)
image_probe_base=$(docker image inspect mcp-writ-kata-probe-base:test --format '{{.Id}}' 2>/dev/null)
image_probe_secure=$(docker image inspect mcp-writ-kata-probe-secure:test --format '{{.Id}}' 2>/dev/null)
guest_kernel=$(timeout 120 docker run --rm --runtime kata --entrypoint /bin/uname mcp-writ-kata-probe-base:test -r 2>/dev/null)

result=vm-tests-passed
rm -rf -- "$work" && work_cleanup=passed
emit_result "$(source_hashes)"
echo "Validation record: $run_dir"
