#!/usr/bin/env bash
# PR-19/25 Apple `container` VM validation job. Run on a macOS arm64
# host meeting the environment in docs/validation/apple-container.md:
# Apple's `container` CLI with the system and builder running, the
# aarch64/x86_64 linux-musl targets, image pull access, and rustc.
# Produces an evidence bundle under .local/apple-validation/<utc>-<uuid>/
# and exits non-zero when the environment, the tests, or the evidence is
# missing — an unexecuted or unevidenced run is never a pass.
set -u -o pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
stamp=$(date -u +%Y%m%d-%H%M%S)-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
run_dir="$repo/.local/apple-validation/$stamp"
work="$run_dir/work"
evidence="$run_dir/evidence"
log="$run_dir/test-output.txt"
result_json="$run_dir/result.json"
mkdir -p "$work" "$evidence" || { echo "cannot create $run_dir" >&2; exit 1; }

jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# BSD date has no %N — milliseconds come from the system perl instead.
utcnow() {
    perl -MTime::HiRes=gettimeofday -MPOSIX=strftime \
        -e '($s,$u)=gettimeofday; printf "%s.%03dZ", strftime("%Y-%m-%dT%H:%M:%S", gmtime($s)), $u/1000'
}

result=failed
commit=unknown
started_utc=$(utcnow)
work_cleanup=skipped

emit_result() {
    local hashes="$1"
    cat >"$result_json" <<EOF
{"vm_requested":true,"result":"$result","started_utc":"$started_utc","finished_utc":"$(utcnow)","commit":"$commit","host":{"os":"$(jstr "$(uname -s)")","kernel":"$(jstr "$(uname -r)")","distro":"$(jstr "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))")","arch":"$(uname -m)"},"rustc":"$(jstr "$(rustc --version 2>/dev/null || echo unavailable)")","container_cli":"$(jstr "${container_version:-unavailable}")","container_system":"$(jstr "${container_status:-unavailable}")","container_builder":"$(jstr "${container_builder:-unavailable}")","images":{"base":"$(jstr "${image_base:-unavailable}")","secure":"$(jstr "${image_secure:-unavailable}")"},"tests":{"passed":${tests_passed:-0},"failed":${tests_failed:-0},"ignored":${tests_ignored:-0}},"evidence":{"metrics":${metrics_count:-0},"lifecycle":${lifecycle_count:-0},"dir":"$evidence"},"work_cleanup":"$work_cleanup","error":"$(jstr "${error:-}")","source_hashes":[$hashes]}
EOF
}

fail() {
    error="$*"
    echo "validate-apple-container: $*" >&2
    emit_result "$(source_hashes)"
    rm -rf -- "$work" 2>/dev/null
    echo "Validation record: $run_dir" >&2
    exit 1
}

source_hashes() {
    local hasher="sha256sum"
    command -v sha256sum >/dev/null 2>&1 || hasher="shasum -a 256"
    (
        cd "$repo" || exit 0
        for f in tests/apple_container_vm_e2e.rs scripts/validate-apple-container.sh \
            src/container/backends/apple.rs src/bin/mcp-secure-runner.rs; do
            [ -f "$f" ] && $hasher "$f"
        done
        find tests/fixtures/kata -type f -exec $hasher {} + 2>/dev/null
    ) | awk '{printf "%s{\"path\":\"%s\",\"sha256\":\"%s\"}", (NR>1?",":""), $2, $1}'
}

# ── environment gate — fail closed before any test work ─────────────
[ "$(uname -s)" = "Darwin" ] || fail "the host must be macOS (Apple container runs nowhere else)"
[ "$(uname -m)" = "arm64" ] || fail "the host must be arm64"
command -v container >/dev/null 2>&1 || fail "the Apple 'container' CLI is not on PATH"
container_version=$(container --version 2>/dev/null | head -1)
container_status=$(container system status 2>/dev/null | head -1)
container system status 2>/dev/null | grep -qi 'running' \
    || fail "'container system status' does not report running — start the substrate first"
# The builder VM is started lazily by `container build` — record its
# state but do not gate on it; a build that cannot start fails the run
# honestly inside the suite.
container_builder=$(container builder status 2>/dev/null | head -1)
rustc --version >/dev/null 2>&1 || fail "rustc is not on PATH (probe compile)"
commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)

# ── disk headroom (AGENTS.md): <40 GiB → cargo clean, then still fail ──
target_dir=$(cargo metadata --locked --no-deps --format-version 1 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
low_space=false
for d in "$target_dir" "$work"; do
    [ -n "$d" ] || continue
    avail=$(df -k "$d" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d ' ')
    [ -n "$avail" ] && [ "$avail" -lt 41943040 ] && low_space=true
done
if $low_space; then
    (cd "$repo" && cargo clean)
fi
for d in "$target_dir" "$work"; do
    [ -n "$d" ] || continue
    avail=$(df -k "$d" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d ' ')
    if [ -n "$avail" ] && [ "$avail" -lt 41943040 ]; then
        fail "$d has less than 40 GiB free after cargo clean"
    fi
done

# ── run the gated suite — the env vars make unexecuted legs fail ─────
export MCP_WRIT_REQUIRE_APPLE_TESTS=1
export MCP_WRIT_APPLE_TEST_ROOT="$work"
export MCP_WRIT_APPLE_EVIDENCE_DIR="$evidence"
export CARGO_INCREMENTAL=0
export TMPDIR="$work"

cd "$repo"
cargo test --locked --test apple_container_vm_e2e -- --nocapture 2>&1 | tee "$log"
test_code=${PIPESTATUS[0]}

read -r tests_passed tests_failed tests_ignored <<<"$(
    awk '/test result:/{
        for(i=1;i<=NF;i++){
            if($i=="passed;")p+=$(i-1); if($i=="failed;")f+=$(i-1); if($i=="ignored;")g+=$(i-1)
        }} END{print p+0, f+0, g+0}' "$log"
)"

if [ "$test_code" -ne 0 ] || [ "$tests_failed" -gt 0 ]; then
    fail "apple_container_vm_e2e failed: ${tests_passed:-0} passed, ${tests_failed:-0} failed (see $log)"
fi
if [ "${tests_passed:-0}" -lt 10 ] || [ "${tests_ignored:-0}" -gt 0 ]; then
    fail "expected all 10 apple tests executed, got passed=${tests_passed:-0} ignored=${tests_ignored:-0} — an unexecuted leg is not a pass"
fi

# ── evidence completeness — a pass without its record is not a pass ──
metrics_count=0
lifecycle_count=0
for m in "$evidence"/*/metrics.json; do
    [ -e "$m" ] || continue
    metrics_count=$((metrics_count + 1))
    d=$(dirname "$m")
    # product (run-image) sessions prove the VM boundary via the host
    # launch report (the guest report is embedded in it) + host identity;
    # harness (`container run`) sessions via the guest report file.
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
done
[ "$metrics_count" -eq 2 ] || fail "expected 2 session metrics records, got $metrics_count"
[ "$lifecycle_count" -eq 4 ] || fail "expected 4 lifecycle records, got $lifecycle_count"

# ── image version for the record ─────────────────────────────────────
# `container image inspect` prints a JSON record; the digest field is
# the durable identity of the wrapped image the launch used.
image_base=$(grep -o 'gcr.io/distroless/static-debian12@sha256:[a-f0-9]*' tests/apple_container_vm_e2e.rs | head -1)
image_secure=$(container image inspect mcp-writ-apple-secure:test 2>/dev/null \
    | grep -o '"digest":"[^"]*"' | head -1 | cut -d'"' -f4)

result=vm-tests-passed
rm -rf -- "$work" && work_cleanup=passed
emit_result "$(source_hashes)"
echo "Validation record: $run_dir"
