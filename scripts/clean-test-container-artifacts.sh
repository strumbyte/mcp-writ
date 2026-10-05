#!/usr/bin/env bash
# Reclaim disk from container-test artifacts left by interrupted or
# failed e2e runs.
#
# What the suites leave behind:
#   - tagged images: docker `mcp-writ-test-*`, `mcp-writ-ctrz-e2e-*`,
#     `mcp-writ-kata-*`, `mcp-writ-hyperv-*`; apple `container` store
#     `mcp-writ-apple-*` plus the e2e's digest-pinned
#     `distroless/static-debian12` base pull
#   - named units: apple `apple-e2e-*` containers (a leaked `--rm` run)
#   - builder cache (`docker build` layers accumulate every run even
#     when the tagged image is removed on success)
#   - orphaned `docker build` / `container build` CLIs when a test run
#     is interrupted mid-build (test builds now kill_on_drop, but older
#     runs and process kills can still detach one)
#
# Everything removed here is test-generated and regenerable. Deletion
# stays inside the named test boundary — `mcp-writ-*` images,
# `apple-e2e-*` units, the pinned e2e base — never a blanket prune
# (`docker system prune -a`, `container image prune`) and never store
# directories by hand. A stopped/unavailable engine is reported and
# skipped, never force-repaired.
set -u

say() { printf '%s\n' "$*"; }

say "== df (before) =="
df -h / | tail -1

# An engine probe can block indefinitely against a hung daemon — a bare
# `docker info` deadlocked this script for minutes on a macOS host whose
# Docker.app was up but the engine unresponsive (the tests' own
# `docker_available` bounds the same probe for this reason). GNU
# `timeout` is not a macOS builtin, so this is a plain watchdog: the
# command's own status on completion, 137 when it had to be killed —
# either way a wedged engine is reported+skipped, never waited on.
probe() {
    local limit=$1; shift
    "$@" &
    local pid=$!
    ( sleep "$limit"; kill -9 "$pid" 2>/dev/null ) &
    local watchdog=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill "$watchdog" 2>/dev/null
    wait "$watchdog" 2>/dev/null
    return "$rc"
}

# --- orphaned test build processes -------------------------------------
# A `docker build`/`container build` tagged mcp-writ-* that outlived its
# test keeps writing to the engine's disk. Report and kill only those —
# the match is a build CLI invocation carrying a test tag, not just any
# process whose command line happens to mention both.
say "== orphaned test build processes =="
orphans=$(pgrep -fl '(^|[ /])(docker|podman|container) +build ' 2>/dev/null \
    | grep -E 'mcp-writ-(test|ctrz-e2e|kata|apple)' || true)
if [ -n "$orphans" ]; then
    say "$orphans"
    printf '%s\n' "$orphans" | awk '{print $1}' | xargs kill 2>/dev/null || true
    say "killed the test-tagged build processes above"
else
    say "none"
fi

# --- docker ------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    say "== docker artifacts =="
    if probe 10 docker info >/dev/null 2>&1; then
        # Leftover test containers (unique_image_name("extract") etc.)
        docker ps -a --format '{{.ID}} {{.Names}}' \
            | grep -E 'mcp-writ-(test|ctrz-e2e|kata|hyperv)-' \
            | awk '{print $1}' \
            | xargs -r docker rm -f >/dev/null 2>&1 || true
        # Test-tagged images
        docker images --format '{{.Repository}}:{{.Tag}}' \
            | grep -E '^mcp-writ-(test|ctrz-e2e|kata|hyperv)-' \
            | tee /dev/stderr \
            | xargs -r docker image rm >/dev/null 2>&1 || true
        # Builder cache — regenerable; this is where interrupted runs
        # accumulate the most (a `cargo build` inside docker leaves GBs).
        docker builder prune -f 2>/dev/null | tail -2
    else
        say "docker daemon unreachable — restart Docker, then re-run"
    fi
else
    say "== docker: not installed =="
fi

# --- docker.exe (Windows-mode daemon) ----------------------------------
# Under WSL/Git-Bash `docker` above can resolve to a Linux engine while
# the Windows daemon — which holds the Hyper-V e2e's `mcp-writ-hyperv-*`
# images (multi-GB Windows Server Core layers) — is only reachable via
# `docker.exe`. Clean its test tags when it answers in Windows mode; a
# Linux-mode or unreachable `docker.exe` is skipped silently.
if command -v docker.exe >/dev/null 2>&1; then
    if [ "$(probe 10 docker.exe info --format '{{.OSType}}' 2>/dev/null)" = "windows" ]; then
        say "== docker.exe (windows daemon) artifacts =="
        docker.exe ps -a --format '{{.ID}} {{.Names}}' \
            | grep -E 'mcp-writ-hyperv-' \
            | awk '{print $1}' \
            | xargs -r docker.exe rm -f >/dev/null 2>&1 || true
        docker.exe images --format '{{.Repository}}:{{.Tag}}' \
            | grep -E '^mcp-writ-hyperv-' \
            | tee /dev/stderr \
            | xargs -r docker.exe image rm >/dev/null 2>&1 || true
        docker.exe builder prune -f 2>/dev/null | tail -2
    fi
fi

# --- Apple container ----------------------------------------------------
if command -v container >/dev/null 2>&1; then
    say "== apple container artifacts =="
    # `system status` exits nonzero when stopped — the output alone is
    # ambiguous ("apiserver is not running …" still matches /running/).
    if status=$(container system status 2>/dev/null) && printf '%s\n' "$status" | grep -q running; then
        # Test units then test-tagged images plus the e2e's pinned
        # distroless base pull (`container image pull --platform …`
        # restores it). `--quiet` prints the unit id / full image
        # reference itself, so no JSON or table field can false-match —
        # and `rm` takes the printed values verbatim.
        container list --all --quiet 2>/dev/null \
            | grep -E '^apple-e2e-' \
            | xargs -r container rm -f >/dev/null 2>&1 || true
        container image ls --quiet 2>/dev/null \
            | grep -E '(^|/)mcp-writ-apple-|distroless/static-debian12@sha256:d75cdd' \
            | tee /dev/stderr \
            | xargs -r container image rm 2>&1 || true
    else
        say "container system not running — start it (container system start), then re-run"
    fi
else
    say "== apple container: not installed =="
fi

say "== df (after) =="
df -h / | tail -1
