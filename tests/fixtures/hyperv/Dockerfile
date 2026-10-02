# Prototype image for the Hyper-V isolated Windows container validation
# (PR-20; see docs/validation/windows-hyperv.md and tests/hyperv_vm_e2e.rs).
#
# The base image is pinned by digest at build time (`--build-arg
# BASE_IMAGE=mcr.microsoft.com/windows/servercore@sha256:…`) — the test
# owns the pin so the recorded validation and the durable test share the
# same base.
#
# No RUN steps: the file layout is COPY-only so `docker build` never
# launches a process-isolated build container (a build-time RUN would
# fail host/image build mismatch on a newer host). Directories the
# workload needs either come from bind mounts at `docker run` time
# (workspace, logs, report, policy) or are created by the image via
# WORKDIR (an empty WORKDIR creates the directory without a RUN).
#
# escape stays default (backslash ` escapes would swallow newlines in
# Windows paths; we write forward slashes everywhere).

ARG BASE_IMAGE=mcr.microsoft.com/windows/servercore:ltsc2025
FROM ${BASE_IMAGE}

# Runner is PID 1; the probe is the workload it wraps. The runner's
# hardcoded contract paths are Linux-spelled (/etc/mcp-secure/policy.kdl,
# /var/log/mcp-secure, /run/mcp-secure/report): on Windows they resolve
# root-relative to the CWD drive, so WORKDIR C:/ lands them under C:\.
COPY mcp-secure-runner.exe C:/mcp-secure/mcp-secure-runner.exe
COPY hyperv-probe.exe C:/mcp-secure/hyperv-probe.exe
# Server Core does not ship the MSVC CRT — the guest would fail loader
# lock with STATUS_DLL_NOT_FOUND (0xC0000135). App-local placement next
# to the exes is the supported redistribution form; the test copies the
# host's vcruntime140.dll into the build context.
COPY vcruntime140.dll C:/mcp-secure/vcruntime140.dll
COPY policy.kdl C:/etc/mcp-secure/policy.kdl

# In-image deny-zone: `C:\writ-deny` exists (WORKDIR creates it) but is
# never granted — the AppContainer DACL layer is what must deny writes
# there while `create_file` in the granted workspace succeeds.
WORKDIR C:/writ-deny
WORKDIR C:/

# The workload the runner restores. MCP_WRIT_* channel vars are baked
# empty so an image default can never divert a launch; the launch still
# passes MCP_WRIT_SERVER / MCP_WRIT_LAUNCH_ID / MCP_WRIT_REPORT_OUT.
ENV MCP_ORIG_ENTRYPOINT="[\"C:/mcp-secure/hyperv-probe.exe\"]" \
    MCP_ORIG_CMD="" \
    MCP_WRIT_ENV="" \
    MCP_WRIT_SERVER="" \
    MCP_WRIT_SKIP_SANDBOX="" \
    MCP_WRIT_FAIL_ON=""

ENTRYPOINT ["C:/mcp-secure/mcp-secure-runner.exe"]
