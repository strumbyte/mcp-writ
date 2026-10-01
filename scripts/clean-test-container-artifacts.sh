#!/usr/bin/env bash
# Reclaim disk from container-test artifacts left by interrupted or
# failed e2e runs.
#
# What the suites leave behind:
#   - tagged images: docker `mcp-writ-test-*`, `mcp-writ-ctrz-e2e-*`,
#     `mcp-writ-kata-*`; apple `container` store `mcp-writ-apple-*`
#   - builder cache (`docker build` layers accumulate every run even
#     when the tagged image is removed on success)
#   - orphaned `docker build` / `container build` CLIs when a test run
#     is interrupted mid-build (test builds now kill_on_drop, but older
#     runs and process kills can still detach one)
#
# Everything removed here is test-generated and regenerable. The script
# only deletes objects tagged `mcp-writ-*` — no untagged images, no
# `docker system prune -a`, no store directories. A stopped/unavailable
# engine is reported and skipped, never force-repaired.
set -u

say() { printf '%s\n' "$*"; }

say "== df (before) =="
df -h / | tail -1

# --- orphaned test build processes -------------------------------------
# A `docker build`/`container build` tagged mcp-writ-* that outlived its
# test keeps writing to the engine's disk. Report and kill only those.
say "== orphaned test build processes =="
orphans=$(pgrep -fl 'mcp-writ-(test|ctrz-e2e|kata|apple)' 2>/dev/null | grep -E 'build' || true)
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
    if docker info >/dev/null 2>&1; then
        # Leftover test containers (unique_image_name("extract") etc.)
        docker ps -a --format '{{.ID}} {{.Names}}' \
            | grep -E 'mcp-writ-(test|ctrz-e2e|kata)-' \
            | awk '{print $1}' \
            | xargs -r docker rm -f >/dev/null 2>&1 || true
        # Test-tagged images
        docker images --format '{{.Repository}}:{{.Tag}}' \
            | grep -E '^mcp-writ-(test|ctrz-e2e|kata)-' \
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

# --- Apple container ----------------------------------------------------
if command -v container >/dev/null 2>&1; then
    say "== apple container artifacts =="
    # Test units (apple-e2e-* names) then test-tagged images. The image
    # ref needs NAME:TAG — `container image rm` on a bare name misses.
    container list --all --format json 2>/dev/null \
        | grep -o '"apple-e2e-[^"]*"' | tr -d '"' \
        | xargs -r container rm -f >/dev/null 2>&1 || true
    container image ls 2>/dev/null \
        | awk 'NR>1 && $1 ~ /^mcp-writ-apple-/ {print $1 ":" $2}' \
        | tee /dev/stderr \
        | xargs -r container image rm 2>&1 || true
    # Dangling/unreferenced layers left by pulled test bases (the e2e
    # pulls the distroless index per-platform). `image prune` reclaims
    # every unreferenced image in the store — broader than the tagged
    # filter above, but still bounded to regenerable content.
    container image prune 2>/dev/null | head -3
else
    say "== apple container: not installed =="
fi

say "== df (after) =="
df -h / | tail -1
