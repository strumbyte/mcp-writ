#!/usr/bin/env bash
# release-preflight — refuse a release commit whose required verification
# has not passed on that exact commit.
#
# Usage:
#   scripts/release-preflight.sh [<commit>]    (default: HEAD)
#
# The Release workflow re-runs CI, Platform tests, Container tests, and Go
# runtime only after the tag is pushed, and Linux tests and MCP server
# verification never run from it. All six are manual-dispatch on branches,
# so a change one of them covers can stay unexercised until the tag — the
# v0.5.0 tag hit a containerize hardening that Container tests had not run
# since ten days earlier. This check is read-only: each required workflow
# must have a successful run whose head commit is the commit to be tagged
# (the pre-release checklist in docs/test-matrix.md). Runs on a branch head
# do not count for the merge commit that lands it.
#
# Requires: git, and gh authenticated for the repository.
set -u

commit=$(git rev-parse --verify "${1:-HEAD}^{commit}") || exit 2
missing=0
for workflow in ci.yml platform-tests.yml container-tests.yml go-runtime.yml \
    linux-tests.yml mcp-servers.yml; do
    url=$(gh run list --workflow "$workflow" --commit "$commit" --status success \
        --limit 1 --json url --jq '.[0].url // empty') || exit 2
    if [ -n "$url" ]; then
        printf 'ok       %-20s %s\n' "$workflow" "$url"
    else
        printf 'MISSING  %-20s no successful run on %s\n' "$workflow" "$commit"
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    printf '\nDispatch the missing workflows on %s and re-run this check\n' "$commit"
    printf 'before pushing the tag.\n'
    exit 1
fi
printf '\nAll required verification passed on %s.\n' "$commit"
