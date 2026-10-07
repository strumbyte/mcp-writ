# Security Review: mcp-writ

## Scope

Standard single-pass security audit of the entire mcp-writ repository at immutable revision 562ea1851fc6daa995f99146038b1168a0d35fa7.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_65dbda789be9b0b19077db239957e3dbd0dc4ebb27a4c2904b4871cc14eeba1c
- Revision: 562ea1851fc6daa995f99146038b1168a0d35fa7
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: repository source and configuration, tests and fixtures, documentation and runnable examples, GitHub Actions workflows and development scripts
- Scan context: Review covered the Auditor, MCP protocol decisions, Warden mechanisms, container and VM backends, staging, policy generation, Inspector, fixtures, examples, and release/development automation.

Limitations and exclusions:
- External container engines, kernels, Windows ACL state, GitHub repository configuration, and deployed policies were not available for runtime validation.
- Race conditions and cleanup failure paths were validated from implementation and control flow rather than reproduced on live platforms.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 15 |
| Severity mix | medium: 12, low: 3 |
| Confidence mix | high: 15 |
| Coverage | complete |
| Validation mode | Offline static source review with an independent baseline, focused parallel investigators, parent source-flow validation, and attack-path severity calibration. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

mcp-writ is a local CLI control plane for stdio MCP servers. The native path loads and binds a KDL policy, verifies configured hashes, launches through a platform-specific Warden, and relays client/server JSON-RPC through the Auditor (README.md:31-53, src/main.rs:182-211, src/runtime/launch.rs:122-140, src/runtime/launch.rs:314-396). Image workflows launch a wrapped image whose PID 1 is mcp-secure-runner; host-supplied read-only policy and writable audit/report channels cross the engine or VM boundary, and the guest runner revalidates policy before launching the original command (src/container/runner.rs:580-837, src/bin/mcp-secure-runner.rs:205-220, src/bin/mcp-secure-runner.rs:301-360). Conditional privileged surfaces include policy generation with opt-in live execution/self-test, image wrapping/containerization, Windows Sandbox staging/relay, and the tag-triggered release workflow (src/commands/generate_policy.rs:13-42, src/container/sandbox.rs:135-200, .github/workflows/release.yml:3-35).

### Assets

- Host filesystem contents and secret-bearing paths reachable by the MCP server; secret-path overlay and OS filesystem rules are separate controls (src/policy/mod.rs:393-413, src/auditor/checker.rs:29-51).
- Host and guest network/process authority represented by effective policy and sandbox capabilities (src/policy/mod.rs:450-490, src/warden/mod.rs:147-215).
- Integrity and server-specific binding of policy, tool set, tools/list manifest, launch executable/payload, image digest, runner, and generated image (src/policy/mod.rs:675-750, src/runtime/launch.rs:236-319, src/container/runner.rs:651-703).
- MCP protocol integrity and availability, including request admission, tools/list filtering/revalidation, bounded framing, and session-state limits (src/auditor/proxy.rs:13-25, src/framing.rs:9-11, src/auditor/session.rs:221-230).
- Audit JSONL and launch-report integrity, correlation IDs, policy hashes, guest self-reports, and Windows Sandbox state (src/audit_log.rs:179-215, src/container/guest_report.rs:299-305, src/container/sandbox.rs:460-465).
- Build inputs and outputs: application source, runner binaries, effective policy, generated Dockerfiles, image tags/digests, release archives, and checksums (src/container/common.rs:354-420, src/container/containerize.rs:152-200, .github/workflows/release.yml:339-408).
- Windows Sandbox relay credentials and state under the operator-selected sandbox-state directory; literal credential values are excluded (src/container/backends/windows_sandbox.rs:130-155, src/fspriv.rs:32-70).

### Trust Boundaries

- MCP client -\> Auditor -\> MCP server: client-controlled JSON-RPC is parsed, framed, authorized, schema/path/host/secret/trajectory checked, tools/list filtered, and audited. The server controls responses and advertised tools. Dry-run forwards tool-call violations and is a distinct operator-selected boundary (src/auditor/proxy.rs:13-25, src/auditor/checker.rs:144-274, src/runtime/launch.rs:393-418).
- Operator policy/configuration -\> loader -\> bound enforcement state: includes/extends resolve relative to source policies and are merged before target validation; bind_to_server removes other server grants (src/policy/loader.rs:17-47, src/policy/kdl_inherit.rs:31-76, src/policy/mod.rs:675-733).
- mcp-writ parent -\> native child: the child is launched under Linux no_new_privs/Landlock/seccomp, macOS sandbox-exec, Windows AppContainer, or explicit PSEC; Warden owns these OS controls and unsupported explicit mechanisms refuse (src/warden/mod.rs:76-112, src/warden/mod.rs:147-215, src/warden/mod.rs:414-507).
- Host CLI -\> local container engine/substrate -\> guest runner: a typed LaunchSpec crosses to a backend that must confirm requested isolation. Engine/daemon authority is external; common remote endpoints are refused because bind mounts would target another machine (src/container/backends/mod.rs:72-133, src/container/backends/mod.rs:195-221, src/container/guest_report.rs:244-285, src/container/runner.rs:419-431).
- Guest runner -\> original server: the runner consumes and strips policy/audit/report/temp channel variables plus MCP_WRIT_SKIP_SANDBOX, reconstructs ENTRYPOINT/CMD, binds policy, and invokes the launch pipeline with sandbox skipping disabled (src/bin/mcp-secure-runner.rs:157-220, src/bin/mcp-secure-runner.rs:260-360).
- Guest-writable report mount -\> host parser: report content is self-reported and is constrained by regular-file/no-symlink, 8 MiB, UTF-8/JSON/schema, launch-ID, runner-version, and capability checks before attachment (src/container/guest_report.rs:299-468).
- Windows Sandbox host -\> disposable guest: owner-only state maps read-only C:\\relay-ro and writable C:\\relay-rw; plaintext Default Switch relay uses per-launch bearer proofs and explicitly trusts the host/management/guest-relay/switch without attestation or network confidentiality (src/container/sandbox.rs:40-56, src/container/sandbox.rs:487-555, src/container/backends/windows_sandbox.rs:137-206).
- Source/policy/runner -\> private build context -\> engine -\> image: wrap/containerize inline effective policy and runner; containerize recursively copies non-excluded, non-symlink source entries, so the engine/image receive those files (src/container/common.rs:354-528, src/container/containerize.rs:152-200, src/fspriv.rs:189-199).
- Developer -\> generate-policy live discovery/self-test: static is default; live discovery executes the command without Warden but with a restricted environment, unsafe mode inherits ambient environment, and self-test is separately opt-in and Warden-backed (src/commands/generate_policy.rs:13-42, src/commands/generate_policy.rs:97-119, src/legislator/tools_list.rs:430-495).
- Git tag/repository -\> GitHub Actions -\> public release: v\* tags trigger version gates, builds/tests, runner validation, packaging/checksums, and a final contents:write release job; external tag authorization is absent from source (.github/workflows/release.yml:3-65, .github/workflows/release.yml:115-207, .github/workflows/release.yml:319-408).

### Attacker Capabilities

- An untrusted MCP client controls JSON-RPC frames, tool names/arguments, request IDs, retries, and sequencing, but not operator policy, launcher environment, audit/report destinations, or OS account.
- A malicious MCP server controls responses, tools/list, notifications, and child-side actions allowed by its actual sandbox, but not the parent or policy before a boundary failure.
- A malicious guest workload can write guest-writable shares and self-report, but lacks arbitrary host filesystem access outside mapped shares.
- A same-user operator or compromised launcher can choose policy, command, dry-run/skip-sandbox, image/build options, paths, and mounts; this is already deployment authority.
- A repository contributor can alter code/workflows/build inputs subject to review, while release additionally needs external v\* tag and contents:write authority.
- A failure could add host file access, network/process authority, unlisted tool invocation, cross-server grants, report spoofing, source exposure to a build engine/image, or unauthorized publication, subject to prerequisites.

### Security Objectives

- Bind runtime to one validated effective policy/server identity and fail closed on inexpressible or non-round-tripping policy state (src/policy/mod.rs:675-797).
- Resolve, verify, bind, and reverify pinned launch artifacts before execution, and reject unbindable inline evaluation or mismatched image digests (src/runtime/launch.rs:236-319, src/container/runner.rs:651-689).
- Default-deny unknown tools and enforce schema, secret, filesystem/network, side-effect/input-response, and session controls before forwarding (src/auditor/checker.rs:134-274).
- Keep OS Warden enforcement distinct from RPC argument inspection; per-tool RPC checks do not prove server-internal confinement (src/warden/mod.rs:147-215).
- Apply environment restrictions even when OS sandboxing is skipped and scrub host/guest channel variables before original workload launch (src/runtime/launch.rs:178-185, src/warden/env.rs:14-46, src/bin/mcp-secure-runner.rs:191-202).
- With logging.fail_closed, require/open audit storage and stop enforcement on logger failure; preserve audit/launch correlation and never write reports on MCP stdout (src/main.rs:234-269, src/audit_log.rs:268-299).
- Mount policy read-only, separate writable audit/report channels, refuse known remote daemons, and never treat guest reports as host-observed controls (src/container/runner.rs:715-837, src/container/runner.rs:940-955).
- Require exact requested isolation and cleanup ownership, with no weaker fallback for unsupported combinations (src/container/backends/mod.rs:122-254, src/container/runner.rs:341-380).
- Protect temporary contexts and relay credentials; exclude common secret/build directories and symlinks from containerize staging (src/fspriv.rs:7-70, src/container/common.rs:463-528).
- Limit publication to verified artifacts, minimal permissions, tag/version agreement, capability/import checks, and checksums (.github/workflows/release.yml:12-65, .github/workflows/release.yml:319-408).

### Assumptions

- No SECURITY.md or authoritative knowledge base was supplied. Scope is repository HEAD 562ea1851fc6daa995f99146038b1168a0d35fa7; no production exposure or tenant model is assumed.
- One MCP client and child per instance is the normal boundary; process-local deputy/trajectory state is shared by any multiplexed clients, so tenant isolation must not be inferred (src/auditor/proxy.rs:41-57, src/auditor/session.rs:143-146).
- Dry-run and MCP_WRIT_SKIP_SANDBOX are operator inputs. Dry-run forwards violations; skip-sandbox leaves Auditor blocking active. Untrusted impact needs launcher control (src/main.rs:273-305, src/runtime/launch.rs:320-335).
- Native temp comments say workload_tmpdir=None retains host temp variables, while macOS Warden actually creates and injects a private per-launch temp directory (src/main.rs:301-304, src/runtime/launch.rs:53-56, src/warden/mod.rs:551-640).
- The guide calls run-image log mounts optional, but default fail-closed logging refuses if the guest default log directory is absent; generated wrap Dockerfiles do not create it (docs/guide.md:220-224, src/bin/mcp-secure-runner.rs:301-338, src/policy/mod.rs:494-506, src/container/dockerfile.rs:118-242).
- Containerize assumes Linux after base-image inspection failure; run-image later rechecks OS and entrypoint (src/container/containerize.rs:88-108, src/container/runner.rs:480-532).
- Remote-daemon checks do not cover every context-selected remote; guest reports remain guest-self-reported; Windows Sandbox relay is authenticated but plaintext on a trusted switch.
- Live discovery executes code without Warden; unsafe discovery additionally inherits ambient environment.
- Release integrity depends on external GitHub permissions absent from the checkout.
- Architecture mapping is not completed security-audit coverage; external engines, kernels, hosted configuration, and deployments remain external.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [A reused AppContainer SID can inherit stale filesystem grants after abnormal cleanup](#finding-1) | medium | high | inline below |
| [Engine-backed cleanup reports success without confirming container or VM removal](#finding-2) | medium | high | inline below |
| [Malformed tools/list pages bypass first-seen verification in dry-run](#finding-3) | medium | high | inline below |
| [Dry-run forwards policy-denied server and MRTR requests to the client](#finding-4) | medium | high | inline below |
| [Generated Case-C tools with unproven capabilities are allowed by default](#finding-5) | medium | high | inline below |
| [Unvalidated base image text permits Dockerfile instruction injection](#finding-6) | medium | high | inline below |
| [Quick-start dry-run exposes the full parent environment to an unsandboxed server](#finding-7) | medium | high | inline below |
| [Containerize source staging can follow an attacker-swapped link outside the source tree](#finding-8) | medium | high | inline below |
| [Windows Sandbox payload staging can follow a reparse-point swap into host files](#finding-9) | medium | high | inline below |
| [Cancellation can clear unresolved trajectory effects before the cancelled call finishes](#finding-10) | medium | high | inline below |
| [Fail-closed audit commits acknowledge queue admission rather than durable recording](#finding-11) | medium | high | inline below |
| [Dry-run forwards policy-denied client requests outside tools/call](#finding-12) | medium | high | inline below |
| [Inspector and policy generation process untrusted files without aggregate size limits](#finding-13) | low | high | inline below |
| [tools/list collision diagnostics permit quadratic memory amplification](#finding-14) | low | high | inline below |
| [Hash-pinned workloads are reopened by pathname after final verification](#finding-15) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] A reused AppContainer SID can inherit stale filesystem grants after abnormal cleanup

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | cleanup |
| CWE | CWE-459 |
| Affected lines | src/warden/windows_sandbox.rs:422-430, src/warden/windows_profile.rs:228-262, src/warden/windows_profile.rs:299-355, src/warden/windows_profile.rs:532-589 |

#### Summary

The AppContainer profile name is derived from executable basename and parent PID, yielding the same SID when reused. Filesystem ACE restoration exists only in process memory and Drop ignores restoration/deletion errors, so a later launch can inherit residual grants.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Same profile names produce the same SID, ACEs are inheritable, original DACLs are process-memory-only, and cleanup errors are discarded.

#### Dataflow

After abnormal teardown leaves an AppContainer ACE, PID and profile-name reuse recreates the same SID for a later workload, which can exercise the old grant.

- **Source:** residual filesystem ACE for a deterministic SID

- **Sink:** later process token containing the reused SID

- **Outcome:** the later sandbox accesses paths absent from its policy

#### Reachability

Cleanup must fail and the deterministic name/PID must later be reused.

- **Attacker:** Later untrusted Windows MCP workload

- **Entry point:** AppContainer launch after failed prior cleanup

- **Outcome:** the later sandbox accesses paths absent from its policy

Limitations:
- High for persistent launch services with predictable/recycled PIDs and policies granting high-value writable or secret paths.

#### Severity

**Medium** — Residual ACEs can expose paths removed from a later policy, but exploitation requires abnormal exit or restoration failure followed by profile-name and PID reuse.

High for persistent launch services with predictable/recycled PIDs and policies granting high-value writable or secret paths.

Impact assessment:
- **Level:** medium
- **Why:** Residual ACEs can expose paths removed from a later policy, but exploitation requires abnormal exit or restoration failure followed by profile-name and PID reuse.

Likelihood assessment:
- **Level:** low
- **Why:** Cleanup must fail and the deterministic name/PID must later be reused.

#### Remediation

Use a cryptographically random per-launch profile identity, track launch-specific ACEs in a durable restoration journal, verify each restore and deletion, and recover stale entries before accepting new launches.

<a id="finding-2"></a>

### [2] Engine-backed cleanup reports success without confirming container or VM removal

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | cleanup |
| CWE | CWE-459 |
| Affected lines | src/container/backends/oci.rs:259-286, src/container/backends/oci.rs:319-372, src/container/backends/mod.rs:508-535 |

#### Summary

After terminating the engine CLI, cleanup optionally runs `rm -f` but ignores spawn errors, timeout, and exit status, skips removal when the cidfile is late, then marks the handle cleaned and reports interruption.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Source comments acknowledge CLI termination can leave the daemon unit; cleanup discards every removal outcome and unconditionally sets `cleaned`.

#### Dataflow

An interrupted workload outlives the engine CLI; removal is skipped or fails, but cleanup ignores the result, marks the handle clean, and prevents a retry.

- **Source:** surviving daemon unit

- **Sink:** unverified cleanup success state

- **Outcome:** the workload continues with mounts and network after reported cleanup

#### Reachability

A delayed cidfile or engine removal failure must coincide with interruption.

- **Attacker:** Malicious daemon-backed MCP workload

- **Entry point:** session interruption or cancellation

- **Outcome:** the workload continues with mounts and network after reported cleanup

Limitations:
- High where daemon workloads retain sensitive writable mounts, privileged networking, or host-integrated isolation after the controlling process exits.

#### Severity

**Medium** — An untrusted workload can continue under a daemon with its mounts and network after the command reports cleanup, though the condition depends on interruption plus a delayed identifier or removal failure.

High where daemon workloads retain sensitive writable mounts, privileged networking, or host-integrated isolation after the controlling process exits.

Impact assessment:
- **Level:** medium
- **Why:** An untrusted workload can continue under a daemon with its mounts and network after the command reports cleanup, though the condition depends on interruption plus a delayed identifier or removal failure.

Likelihood assessment:
- **Level:** medium
- **Why:** A delayed cidfile or engine removal failure must coincide with interruption.

#### Remediation

Require a recorded unit ID, check removal spawn and status, poll engine state until absence is confirmed, preserve the cidfile, and keep retry/Drop cleanup enabled whenever confirmation fails.

<a id="finding-3"></a>

### [3] Malformed tools/list pages bypass first-seen verification in dry-run

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | protection_mechanism_failure |
| CWE | CWE-693 |
| Affected lines | src/auditor/proxy_tools_list.rs:374-391, src/auditor/proxy_tools_list.rs:462-552, src/protocol/tools_list.rs:138-203 |

#### Summary

A structurally valid response with malformed optional tool fields triggers a parse error that raw-forwards the original page in dry-run before manifest scanning, hash checks, filtering, and verified rebuilding.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- The parse-error dry-run branch writes the raw line and returns before every first-seen verification step.

#### Dataflow

A dry-run server pairs attacker-controlled tool metadata with a malformed optional field; parsing fails and the raw tools/list page reaches a tolerant client before verification.

- **Source:** malformed but valid-JSON tool definition

- **Sink:** raw response written to the client

- **Outcome:** the client receives unscanned and unpinned tool metadata

#### Reachability

A tolerant downstream client and operator-enabled dry-run are required.

- **Attacker:** Malicious MCP server

- **Entry point:** tools/list response in dry-run

- **Outcome:** the client receives unscanned and unpinned tool metadata

Limitations:
- High if downstream clients tolerate the malformed field and automatically surface or act on attacker-controlled tool descriptions with sensitive context.

#### Severity

**Medium** — A malicious server can expose unverified prompt-injection descriptions or dangerous schema metadata to tolerant clients, but the operator must enable dry-run and strict clients may reject the malformed item.

High if downstream clients tolerate the malformed field and automatically surface or act on attacker-controlled tool descriptions with sensitive context.

Impact assessment:
- **Level:** medium
- **Why:** A malicious server can expose unverified prompt-injection descriptions or dangerous schema metadata to tolerant clients, but the operator must enable dry-run and strict clients may reject the malformed item.

Likelihood assessment:
- **Level:** medium
- **Why:** A tolerant downstream client and operator-enabled dry-run are required.

#### Remediation

Treat every tools/list parse or shape failure as a verification abort in all modes. Return a JSON-RPC verification error and never raw-forward an unverified manifest.

<a id="finding-4"></a>

### [4] Dry-run forwards policy-denied server and MRTR requests to the client

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | authorization |
| CWE | CWE-863 |
| Affected lines | src/auditor/proxy_s2c.rs:629-744, src/auditor/proxy_s2c.rs:789-831, src/auditor/proxy_s2c.rs:923-1017, src/policy/mcp/decide.rs:685-707 |

#### Summary

Server-to-client denials for sampling, roots, elicitation, and additional MRTR requests are raw-forwarded in dry-run, including cases where negotiated capabilities or explicit allow rules are absent.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Both direct deny forwarding and the input-required response branch send the original denied content when dry-run is true.

#### Dataflow

A malicious dry-run server emits a sampling, roots, elicitation, or MRTR request lacking authorization; the proxy raw-forwards it to a capable client.

- **Source:** policy-denied S2C message

- **Sink:** connected MCP client

- **Outcome:** the server solicits model, root, or user data outside policy

#### Reachability

The client must support and act on the forwarded request.

- **Attacker:** Malicious MCP server launched in dry-run

- **Entry point:** server-to-client request or input-required response

- **Outcome:** the server solicits model, root, or user data outside policy

Limitations:
- High where clients automatically satisfy sampling, roots, or elicitation requests with sensitive data and dry-run is used on untrusted servers.

#### Severity

**Medium** — A malicious server can solicit client-side model output or user/root data outside policy, but exploitation requires operator-enabled dry-run and a client that services the forwarded request.

High where clients automatically satisfy sampling, roots, or elicitation requests with sensitive data and dry-run is used on untrusted servers.

Impact assessment:
- **Level:** medium
- **Why:** A malicious server can solicit client-side model output or user/root data outside policy, but exploitation requires operator-enabled dry-run and a client that services the forwarded request.

Likelihood assessment:
- **Level:** medium
- **Why:** The client must support and act on the forwarded request.

#### Remediation

Never relax server-to-client request, notification, response, or MRTR authorization in dry-run. Add regressions for denied sampling, roots, elicitation, and embedded additional requests.

<a id="finding-5"></a>

### [5] Generated Case-C tools with unproven capabilities are allowed by default

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | authorization |
| CWE | CWE-862 |
| Affected lines | src/commands/generate_policy.rs:158-185, src/legislator/cross_validator.rs:319-427, src/legislator/policy_generator.rs:240-293, src/policy/kdl_parse/servers.rs:280-294, src/policy/merge.rs:47-50 |

#### Summary

When source parsing or binding cannot prove a live-discovered tool, policy generation emits a warning-only tool entry without `deny=#true`. Loading that policy defaults the tool to allowed, contrary to the command's fail-secure framing.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Parse failure continues with empty analysis, Case-C is warning-only, the emitted entry omits deny, and merge defaults unspecified authorization to allowed.

#### Dataflow

A malicious server presents a live tool that source analysis cannot bind; generation emits warning-only Case-C policy and effective merge defaults it to allowed when the draft is deployed.

- **Source:** unproven live tool

- **Sink:** effective `ToolPolicy.allowed = true`

- **Outcome:** a high-risk unproven tool is authorized

#### Reachability

The operator must deploy the generated draft without correcting the warning.

- **Attacker:** Actor controlling an analyzed MCP server or source artifact

- **Entry point:** `generate-policy` with live discovery

- **Outcome:** a high-risk unproven tool is authorized

Limitations:
- High where generated policies are automatically accepted or reviewers rely on successful generation/self-test as evidence that unproven tools are denied.

#### Severity

**Medium** — A malicious or dynamically defined tool can pass generated authorization despite unproven high-risk behavior, but the operator must opt into discovery and deploy a prominently labeled draft.

High where generated policies are automatically accepted or reviewers rely on successful generation/self-test as evidence that unproven tools are denied.

Impact assessment:
- **Level:** medium
- **Why:** A malicious or dynamically defined tool can pass generated authorization despite unproven high-risk behavior, but the operator must opt into discovery and deploy a prominently labeled draft.

Likelihood assessment:
- **Level:** medium
- **Why:** The operator must deploy the generated draft without correcting the warning.

#### Remediation

Emit every Case-C or otherwise unproven tool with `deny=#true`; abort or create a deny-only draft when source analysis fails. Extend self-test to assert the effective loaded decision for every Case-C entry.

<a id="finding-6"></a>

### [6] Unvalidated base image text permits Dockerfile instruction injection

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | injection |
| CWE | CWE-94 |
| Affected lines | src/cli/parse_containerize.rs:32-40, src/container/containerize_dockerfile.rs:46-77, src/container/containerize_dockerfile.rs:109-118, src/container/common.rs:553-572 |

#### Summary

`containerize --base-image` is accepted verbatim and interpolated into generated Linux and Windows `FROM` instructions. A failed image inspection is non-fatal, so newline or Dockerfile-token payloads can reach the engine build context.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Verbatim CLI text flows through non-fatal inspection into raw `FROM` string construction and then an actual Docker/Podman/Buildah/wslc build.

#### Dataflow

A caller supplies a base-image string containing Dockerfile syntax; `containerize` renders it into `FROM`, and the selected engine executes the added build instructions.

- **Source:** base-image CLI text

- **Sink:** generated Dockerfile passed to the image builder

- **Outcome:** attacker-selected build instructions alter or expose the build context

#### Reachability

The value is high-trust configuration, but CI wrappers can expose it to lower-trust inputs.

- **Attacker:** Caller who can set `containerize --base-image` for a more-trusted build

- **Entry point:** `containerize --base-image`

- **Outcome:** attacker-selected build instructions alter or expose the build context

Limitations:
- High if an untrusted tenant can set this value in a privileged shared builder with sensitive build secrets or host-level engine entitlements.

#### Severity

**Medium** — A caller who influences a more-trusted build can alter image construction and expose build-context contents, but must control a high-trust CLI value and does not directly escape the engine.

High if an untrusted tenant can set this value in a privileged shared builder with sensitive build secrets or host-level engine entitlements.

Impact assessment:
- **Level:** medium
- **Why:** A caller who influences a more-trusted build can alter image construction and expose build-context contents, but must control a high-trust CLI value and does not directly escape the engine.

Likelihood assessment:
- **Level:** medium
- **Why:** The value is high-trust configuration, but CI wrappers can expose it to lower-trust inputs.

#### Remediation

Parse the value as one strict OCI image reference and reject whitespace, CR/LF, controls, comments, escapes, and extra Dockerfile tokens before inspection or rendering.

Tests:
- Reject values containing newline, carriage return, comments, escape continuations, or multiple tokens.
- Accept valid registry, tag, digest, IPv6, and platform-qualified references.

<a id="finding-7"></a>

### [7] Quick-start dry-run exposes the full parent environment to an unsandboxed server

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | information_exposure |
| CWE | CWE-526 |
| Affected lines | docs/quickstart.md:41-62, docs/quickstart.md:116-123, README.md:108-143, tests/environment_e2e.rs:294-320, src/warden/mod.rs:11-13 |

#### Summary

Runnable quick-start policies omit `defaults.environment` and immediately launch a third-party MCP server with `--dry-run`. Omission intentionally inherits the entire parent environment, while dry-run disables the OS sandbox and its network deny policy.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Tests prove absent environment configuration forwards unlisted parent values, including in bypass modes; the documented command disables Warden immediately after the policy example.

#### Dataflow

A user follows the quick start from a credential-bearing shell; the untrusted server inherits every variable and, because dry-run disables Warden, can send those values over the network.

- **Source:** parent process environment

- **Sink:** unsandboxed child process with network access

- **Outcome:** ambient credentials are disclosed

#### Reachability

The user must run the example from a shell holding useful secrets.

- **Attacker:** Malicious or compromised MCP package

- **Entry point:** documented quick-start dry-run command

- **Outcome:** ambient credentials are disclosed

Limitations:
- High if the quick start is commonly run in developer or CI shells holding production cloud, package, signing, or deployment credentials.

#### Severity

**Medium** — A compromised package can steal shell credentials on startup without a tool call. The flow is explicitly operator-invoked and documentation warns that dry-run is unsandboxed, but recommending test data does not sanitize ambient secrets.

High if the quick start is commonly run in developer or CI shells holding production cloud, package, signing, or deployment credentials.

Impact assessment:
- **Level:** medium
- **Why:** A compromised package can steal shell credentials on startup without a tool call. The flow is explicitly operator-invoked and documentation warns that dry-run is unsandboxed, but recommending test data does not sanitize ambient secrets.

Likelihood assessment:
- **Level:** medium
- **Why:** The user must run the example from a shell holding useful secrets.

#### Remediation

Add an explicit empty environment block to runnable quick-start policies and allow only variables the chosen server demonstrably needs. State that test files do not protect ambient credentials in dry-run.

<a id="finding-8"></a>

### [8] Containerize source staging can follow an attacker-swapped link outside the source tree

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | race_condition |
| CWE | CWE-367 |
| Affected lines | src/container/containerize.rs:408-469, src/container/common.rs:423-452, src/container/common.rs:485-527 |

#### Summary

Source entries are type-checked and later reopened by pathname for copy or recursive traversal. A concurrent rename to a symlink, junction, or reparse point can cause operator-readable files outside the selected tree to enter the build context.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Every guard and later copy/recursion uses a separately resolved pathname; static links are rejected but identity is not retained.

#### Dataflow

While `containerize` stages a mutable source tree, a local actor swaps a checked entry to a link or reparse point; the later pathname copy follows it into an out-of-tree file.

- **Source:** checked source-tree entry name

- **Sink:** private image build context

- **Outcome:** operator-readable host data is embedded in the image

#### Reachability

Concurrent mutation is required, but tenant-controlled workspaces are a realistic automation boundary.

- **Attacker:** Local process able to mutate the selected source tree

- **Entry point:** `containerize` source staging

- **Outcome:** operator-readable host data is embedded in the image

Limitations:
- High if containerization runs automatically on tenant-writable trees while the builder account can read deployment credentials or other high-value files.

#### Severity

**Medium** — The race can copy host secrets into an attacker-controlled image, but requires concurrent local mutation of the explicitly selected source tree.

High if containerization runs automatically on tenant-writable trees while the builder account can read deployment credentials or other high-value files.

Impact assessment:
- **Level:** medium
- **Why:** The race can copy host secrets into an attacker-controlled image, but requires concurrent local mutation of the explicitly selected source tree.

Likelihood assessment:
- **Level:** medium
- **Why:** Concurrent mutation is required, but tenant-controlled workspaces are a realistic automation boundary.

#### Remediation

Traverse from directory handles and copy from already-opened no-follow objects. Enforce beneath-root resolution (`openat2` on Unix and reparse-point-safe handle validation on Windows), or snapshot into an immutable trusted tree first.

<a id="finding-9"></a>

### [9] Windows Sandbox payload staging can follow a reparse-point swap into host files

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | race_condition |
| CWE | CWE-367 |
| Affected lines | src/container/sandbox.rs:223-272, src/container/sandbox.rs:474-510, src/container/backends/windows_sandbox/agent.rs:231-293 |

#### Summary

Payload inventory and copy are separate pathname walks. A mutable entry can become a symlink or reparse point after validation, causing the private read-only share to contain host files outside the chosen payload.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- The no-follow checks precede separately resolved copy and recursion; the whole private staging directory is mapped into the guest.

#### Dataflow

A local actor replaces a validated Windows Sandbox payload entry before the separate copy walk; the mapped guest share then contains an out-of-tree host file.

- **Source:** validated payload entry name

- **Sink:** read-only guest-mapped staging share

- **Outcome:** the guest workload reads operator-readable host data

#### Reachability

The payload must remain attacker-writable during staging.

- **Attacker:** Local process able to mutate the selected payload tree

- **Entry point:** Windows Sandbox payload staging

- **Outcome:** the guest workload reads operator-readable host data

Limitations:
- High when a service stages tenant-controlled payload trees with credentials readable by its Windows account.

#### Severity

**Medium** — A malicious guest can read staged host data, but exploitation requires a concurrent local mutation primitive and a victim-selected mutable payload.

High when a service stages tenant-controlled payload trees with credentials readable by its Windows account.

Impact assessment:
- **Level:** medium
- **Why:** A malicious guest can read staged host data, but exploitation requires a concurrent local mutation primitive and a victim-selected mutable payload.

Likelihood assessment:
- **Level:** medium
- **Why:** The payload must remain attacker-writable during staging.

#### Remediation

Create one immutable snapshot through reparse-point-safe directory/file handles, verify final handle identity and containment, and use only that snapshot for the mapped share and guest copy.

<a id="finding-10"></a>

### [10] Cancellation can clear unresolved trajectory effects before the cancelled call finishes

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | race_condition |
| CWE | CWE-362 |
| Affected lines | src/auditor/proxy_c2s.rs:214-229, src/auditor/proxy_c2s.rs:341-370, src/auditor/session.rs:433-475, src/auditor/session.rs:504-560, src/auditor/proxy_s2c.rs:834-878 |

#### Summary

Cancelling a forwarded tool call removes its pending state and records an unverified side-effect candidate. A successful response for an unrelated call then clears all candidates, even though cancellation is advisory and the original server operation may still complete.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Cancellation deletes the pending entry, later success globally clears candidates, and a late response cannot restore the removed trajectory state.

#### Dataflow

A client cancels a slow side-effecting call, completes an unrelated call to clear unresolved candidates, and then invokes a deny-next tool while cancellation remains only advisory.

- **Source:** pending trajectory state

- **Sink:** global candidate clearing on unrelated success

- **Outcome:** a forbidden cross-tool sequence is accepted while the cancelled effect can still occur

#### Reachability

The server must ignore or delay cancellation and calls must overlap.

- **Attacker:** Untrusted MCP client controlling concurrent calls and cancellation

- **Entry point:** concurrent tools/call plus cancellation

- **Outcome:** a forbidden cross-tool sequence is accepted while the cancelled effect can still occur

Limitations:
- High if trajectory rules guard irreversible financial, administrative, or destructive tool sequences and concurrent calls are exposed to untrusted clients.

#### Severity

**Medium** — The race can bypass deny-next cross-tool sequences and permit a forbidden follow-up while a side effect remains live, but requires concurrency and a server that ignores or delays cancellation.

High if trajectory rules guard irreversible financial, administrative, or destructive tool sequences and concurrent calls are exposed to untrusted clients.

Impact assessment:
- **Level:** medium
- **Why:** The race can bypass deny-next cross-tool sequences and permit a forbidden follow-up while a side effect remains live, but requires concurrency and a server that ignores or delays cancellation.

Likelihood assessment:
- **Level:** medium
- **Why:** The server must ignore or delay cancellation and calls must overlap.

#### Remediation

Retain bounded per-call trajectory tombstones until a definitive response or session end. Never clear unresolved candidates on unrelated success; fail closed when state bounds are reached.

<a id="finding-11"></a>

### [11] Fail-closed audit commits acknowledge queue admission rather than durable recording

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | logging |
| CWE | CWE-778 |
| Affected lines | src/audit_log.rs:372-405, src/audit_log.rs:468-531, src/auditor/proxy_c2s.rs:773-800, src/auditor/proxy_tools_list.rs:645-680 |

#### Summary

`log_committed` returns after a bounded channel send, while file write, flush, and sync occur later in a background task. Protected traffic can therefore be forwarded before the required audit record has reached storage.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- The awaited operation is channel admission; the writer later performs buffered I/O and only publishes failures through shared state.

#### Dataflow

An MCP peer causes a protected operation just before audit storage fails or the process terminates; queue admission succeeds, traffic is forwarded, and the record is never durably written.

- **Source:** audit event for a protected operation

- **Sink:** background buffered audit writer

- **Outcome:** the operation succeeds without its required audit record

#### Reachability

Failure timing is required, but storage and abrupt termination are realistic operational faults.

- **Attacker:** MCP peer able to time activity with storage failure or process loss

- **Entry point:** allowed MCP request or verified tools/list response

- **Outcome:** the operation succeeds without its required audit record

Limitations:
- High where the log is a regulatory or non-repudiation control and the adversary can reliably induce storage failure or process termination after a sensitive operation.

#### Severity

**Medium** — A crash or first asynchronous storage failure can leave an allowed operation without its required audit record, weakening accountability and incident reconstruction. The queue is bounded and already-observed failures do block.

High where the log is a regulatory or non-repudiation control and the adversary can reliably induce storage failure or process termination after a sensitive operation.

Impact assessment:
- **Level:** medium
- **Why:** A crash or first asynchronous storage failure can leave an allowed operation without its required audit record, weakening accountability and incident reconstruction. The queue is bounded and already-observed failures do block.

Likelihood assessment:
- **Level:** medium
- **Why:** Failure timing is required, but storage and abrupt termination are realistic operational faults.

#### Remediation

Attach a per-event acknowledgement completed only after the configured write/flush/sync durability level succeeds, and forward protected traffic only after that acknowledgement.

Tests:
- Inject write, flush, and sync failures and assert that the corresponding RPC is not forwarded.
- Terminate the process after acknowledgement in a deterministic harness and verify committed-event semantics.

<a id="finding-12"></a>

### [12] Dry-run forwards policy-denied client requests outside tools/call

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | authorization |
| CWE | CWE-863 |
| Affected lines | src/auditor/proxy_c2s.rs:575-605, src/auditor/proxy_c2s.rs:622-674, src/policy/mcp/decide.rs:379-475 |

#### Summary

Every client-to-server `McpVerdict::Deny` reaches a helper that forwards the original request whenever dry-run is enabled. The relaxation is not limited to observation of denied tool calls.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- The shared helper checks only `dry_run`; the decision engine emits denials for many non-tool methods.

#### Dataflow

In a dry-run session, an untrusted client sends a non-tool request that policy denies; the generic denial helper forwards the original frame because the mode flag is set.

- **Source:** policy-denied non-tool request

- **Sink:** server stdin through the proxy

- **Outcome:** the denied server operation is invoked

#### Reachability

The operator must deliberately enable dry-run.

- **Attacker:** Untrusted MCP client connected to a dry-run session

- **Entry point:** client-to-server MCP request

- **Outcome:** the denied server operation is invoked

Limitations:
- High if dry-run is exposed as a long-lived multi-tenant service or if denied methods reach high-impact server capabilities outside Warden mediation.

#### Severity

**Medium** — An untrusted client can exercise server resources and operations that effective MCP policy denies, but only after an operator deliberately enables dry-run.

High if dry-run is exposed as a long-lived multi-tenant service or if denied methods reach high-impact server capabilities outside Warden mediation.

Impact assessment:
- **Level:** medium
- **Why:** An untrusted client can exercise server resources and operations that effective MCP policy denies, but only after an operator deliberately enables dry-run.

Likelihood assessment:
- **Level:** medium
- **Why:** The operator must deliberately enable dry-run.

#### Remediation

Represent observation-only tool violations explicitly and permit dry-run forwarding only for that verdict. Continue enforcing lifecycle, capability, URI, subscription, correlation, shape, and non-tool authorization denials.

<a id="finding-13"></a>

### [13] Inspector and policy generation process untrusted files without aggregate size limits

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | resource_exhaustion |
| CWE | CWE-400 |
| Affected lines | src/commands/inspect.rs:18-26, src/commands/generate_policy.rs:148-155, src/legislator/source_bind.rs:608-619, src/inspector/strings.rs:20-96, src/inspector/strings.rs:147-195 |

#### Summary

Local analysis entry points read complete binaries or source files and retain unbounded extracted strings, findings, and clones. A selected large or sparse artifact can force excessive allocation and CPU work.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- Whole files are materialized and string extraction grows and retains attacker-sized collections without aggregate caps.

#### Dataflow

A user or CI job selects an attacker-supplied large binary or source file; whole-file reads and unbounded derived collections exhaust analyzer resources.

- **Source:** attacker-sized file and sections

- **Sink:** unbounded strings, findings, and clone allocations

- **Outcome:** the analysis process stalls or terminates

#### Reachability

The victim must explicitly analyze the local artifact.

- **Attacker:** Actor supplying an artifact selected for analysis

- **Entry point:** `inspect` or `generate-policy` input path

- **Outcome:** the analysis process stalls or terminates

Limitations:
- Medium if a service automatically analyzes untrusted uploads in a shared long-lived process or with consequential availability requirements.

#### Severity

**Low** — The issue can terminate a CLI or CI analysis job, but the victim must explicitly select the attacker-supplied local artifact and no remote exposure was established.

Medium if a service automatically analyzes untrusted uploads in a shared long-lived process or with consequential availability requirements.

Impact assessment:
- **Level:** low
- **Why:** The issue can terminate a CLI or CI analysis job, but the victim must explicitly select the attacker-supplied local artifact and no remote exposure was established.

Likelihood assessment:
- **Level:** low
- **Why:** The victim must explicitly analyze the local artifact.

#### Remediation

Reject inputs above documented maxima, stream or map where practical, and cap per-section bytes, individual string length, total strings/findings, and aggregate retained bytes. Return an explicit incomplete-analysis error.

<a id="finding-14"></a>

### [14] tools/list collision diagnostics permit quadratic memory amplification

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | resource_exhaustion |
| CWE | CWE-770 |
| Affected lines | src/auditor/proxy_list_state.rs:93-99, src/verifier/manifest_rules.rs:632-660, src/verifier/manifest.rs:123-177, src/auditor/proxy_tools_list.rs:481-513 |

#### Summary

The Auditor accumulates tools across up to 50 pages without an aggregate tool budget. For every member of a folded-name collision group it builds a detail containing every name, then clones and concatenates all findings again.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- N colliding tools create N findings whose details each join N names; the Auditor lacks the Legislator's 1,000-tool aggregate bound.

#### Dataflow

A malicious server sends many folded-name collisions across accepted pages; per-member all-name diagnostics expand quadratically and are cloned into audit and blocking strings.

- **Source:** large collision group

- **Sink:** unbounded diagnostic and audit string construction

- **Outcome:** the proxy consumes excessive memory and CPU

#### Reachability

Frame and page limits bound input, and the server may have simpler local denial-of-service options.

- **Attacker:** Malicious MCP server

- **Entry point:** paginated tools/list response

- **Outcome:** the proxy consumes excessive memory and CPU

Limitations:
- Medium if the Auditor is a shared service whose availability protects multiple tenants or the server process itself is more resource-constrained than the proxy.

#### Severity

**Low** — A malicious server can consume substantial unsandboxed proxy CPU and memory, but per-frame/page limits exist and that server may already have other local denial-of-service avenues.

Medium if the Auditor is a shared service whose availability protects multiple tenants or the server process itself is more resource-constrained than the proxy.

Impact assessment:
- **Level:** low
- **Why:** A malicious server can consume substantial unsandboxed proxy CPU and memory, but per-frame/page limits exist and that server may already have other local denial-of-service avenues.

Likelihood assessment:
- **Level:** low
- **Why:** Frame and page limits bound input, and the server may have simpler local denial-of-service options.

#### Remediation

Apply aggregate tool-count and byte limits, emit one bounded finding per collision group, and cap total findings, audit detail length, and blocking-reason length.

<a id="finding-15"></a>

### [15] Hash-pinned workloads are reopened by pathname after final verification

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Static source flow is direct and independently reviewed; runtime reproduction was not required for the control failure. |
| Category | race_condition |
| CWE | CWE-367 |
| Affected lines | src/verifier/hash.rs:336-402, src/runtime/launch.rs:287-335 |

#### Summary

Executable and script hashes are computed from a file handle that is then closed. Warden subsequently launches the canonical pathname, leaving a documented window in which a local actor can replace the verified object.

#### Validation

Validation outcomes are recorded below.

Validation method: offline static source review

- **Disposition:** reportable

Evidence:
- The verifier explicitly documents the residual window; no file identity or handle is carried into the pathname-based spawn.

#### Dataflow

A local path writer replaces a hashed executable or script after the final check and before Warden reopens the pathname for spawn.

- **Source:** verified file pathname

- **Sink:** pathname-based process creation

- **Outcome:** replacement code executes with the verified workload policy

#### Reachability

The race window is narrow and requires local mutation rights.

- **Attacker:** Local actor with write or rename access to the selected workload path

- **Entry point:** runtime launch of a hash-pinned workload

- **Outcome:** replacement code executes with the verified workload policy

Limitations:
- Medium if an untrusted user controls a writable directory containing workloads launched repeatedly by a privileged service.

#### Severity

**Low** — Impact can be high because replacement code inherits the verified workload grants, but exploitation requires precise local write access and race timing on the selected path.

Medium if an untrusted user controls a writable directory containing workloads launched repeatedly by a privileged service.

Impact assessment:
- **Level:** low
- **Why:** Impact can be high because replacement code inherits the verified workload grants, but exploitation requires precise local write access and race timing on the selected path.

Likelihood assessment:
- **Level:** low
- **Why:** The race window is narrow and requires local mutation rights.

#### Remediation

Hash and execute the same open object, or copy verified bytes into a private immutable staging object and launch that object. On Windows, retain replacement-preventing handles through process creation.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Architecture and trust-boundary mapping | Cross-component security model | Reported | Independent architecture mapping completed; not completed source-audit coverage. |
| Baseline review: container image generation and staging | Build context integrity and Dockerfile generation | Reported | Baseline candidates are preserved pending parent validation. |
| Baseline review: fail-closed audit pipeline | Audit durability and enforcement ordering | Reported | Baseline audit candidate pending parent validation. |
| Baseline review: launch artifact identity | Hash pinning and process identity | Reported | Baseline launch hash candidate pending parent validation. |
| Baseline review: framing, policy loading, and path normalization | Protocol framing and policy/path parsing | No issue found | Baseline fully reviewed Cargo.toml, framing, path normalization, policy inheritance/loading, and runtime argv without another candidate. |
| Repository secret-pattern review | Embedded credentials and private keys | No issue found | Offline private-key and common credential searches found no reportable secret. |
| Focused review: container generation and staging | Dockerfile injection and path-based staging races | Reported | Focused investigator independently confirmed base-image Dockerfile injection and separated source-tree and Windows Sandbox staging races; all await parent validation. |
| Focused review: runner staging identity | Runner analysis-to-copy identity | Rejected | The analysis/copy path has a check/use window, but the implemented checks do not authenticate runner origin: an attacker who can persistently replace the path can already supply another format-compatible runner, and unknown formats are explicitly accepted. No new capability was established. Staging the analyzed bytes remains hardening. |
| Focused review: Auditor, MCP policy, tools/list, and session state | RPC authorization, audit durability, manifest verification, and trajectory state | Reported | Focused investigator returned five source-backed candidates awaiting parent validation: queue-only fail-closed audit commit, two generic dry-run authorization bypass families, dry-run tools/list parse bypass, and cancellation/trajectory state race. |
| Focused review: workload identity, policy/Warden, and container backends | Hash pinning, fail-secure sandbox dispatch, engine locality, and guest isolation | Reported | Focused investigator returned four candidates pending parent validation: hash-to-exec race, unsupported-OS unsandboxed fallback, Windows Sandbox staging race, and remote-context locality bypass. |
| Focused review: policy binding and supported-platform Warden controls | Policy inheritance/merge/server binding and supported OS sandbox application | No issue found | No additional fail-open path established: policy files are canonicalized/cycle-checked/merged then validated; deny remains sticky; server selection is exact. Supported Linux/macOS/Windows mechanisms refuse or explicitly gate degradation rather than silently selecting a weaker mechanism. |
| Focused review: backend isolation, guest reports, and Windows Sandbox relay | Isolation confirmation, report trust, and relay authentication | No issue found | Requested backends require exact confirmation and do not fall back; guest reports are bounded/identity-checked but explicitly self-reported; relay tokens are per-launch and mutually proved in an owner-only session. No separate credential or host-command-channel flaw was established. |
| Focused review: tests, fixtures, policies, and documentation contracts | Runnable examples, ambient secrets, fixture reachability, and documented security boundaries | Reported | No embedded real credentials or unintended production fixture reachability was found. Tests corroborate environment inheritance, dry-run forwarding, audit buffering, and the absence of a cancellation-race regression. One quick-start ambient-environment candidate awaits parent validation. |
| Focused review: embedded secrets and fixture production reachability | Source credential exposure and test-only code shipping | No issue found | No PEM private keys or recognizable live provider tokens were found; fixture secrets are demonstrable placeholders. Test-only parser/source fixtures remain cfg(test) or package-excluded, while the Windows relay agent is intentionally shared production code. |
| Focused review: Inspector, policy generation, CLI, scripts, and release workflows | Untrusted static-analysis inputs, generated policy authorization, subprocess and publication safety | Reported | Focused investigator returned two candidates pending parent validation: Case-C generated tools defaulting effectively allowed, and unbounded offline binary/source analysis. No shell/KDL injection, project-root traversal, plan execution fallback, workflow event interpolation, helper cleanup injection, or embedded credential was established. |
| Focused review: development helpers and GitHub workflows | Shell invocation, destructive cleanup, and release publication authority | No issue found | Helpers use argv-safe execution and name-prefix filtering; actions are pinned, checkout credentials disabled, normal jobs read-only, and contents:write is confined to trusted tag release publication. No pull_request_target or event-text shell interpolation path was found. |
| Remaining Warden, container backend, AppContainer, and Auditor verifier paths | Backend lifecycle, Windows ACL isolation, staging integrity, and protocol resource bounds | Reported | Focused source review completed without builds or tests; four new candidates checkpointed for parent validation. |
| Parent validation and severity calibration | Candidate validity, reachability, impact, and duplicate closure | Reported | Validated 15 unique source-backed findings (12 medium, 3 low). Rejected the runner staging compatibility race, marked unsupported-platform fallback not applicable to the supported contract, and suppressed remote-context ambiguity without an attacker-controlled working deployment path. |
| Candidate disposition: baseline-dockerfile-base-image-injection | Validated discovery candidate | Rejected | Duplicate of the validated Dockerfile base-image injection finding. |
| Candidate disposition: baseline-audit-fail-closed-ack | Validated discovery candidate | Rejected | Duplicate of the validated fail-closed audit acknowledgement finding. |
| Candidate disposition: baseline-launch-hash-toctou | Validated discovery candidate | Rejected | Duplicate of the validated hash-to-exec pathname race finding. |
| Candidate disposition: baseline-runner-staging-toctou | Validated discovery candidate | Rejected | Rejected: compatibility checks do not authenticate origin, so path replacement does not create a capability beyond supplying another compatible runner. |
| Candidate disposition: baseline-staging-symlink-race | Validated discovery candidate | Rejected | Aggregate duplicate split into the validated containerize and Windows Sandbox staging findings. |
| Candidate disposition: focused-container-dockerfile-injection | Validated discovery candidate | Reported | Validated and represented by reportable finding: Unvalidated base image text permits Dockerfile instruction injection |
| Candidate disposition: focused-container-source-staging-race | Validated discovery candidate | Rejected | Duplicate of the validated containerize source staging race finding. |
| Candidate disposition: focused-windows-sandbox-staging-race | Validated discovery candidate | Reported | Validated and represented by reportable finding: Windows Sandbox payload staging can follow a reparse-point swap into host files |
| Candidate disposition: focused-audit-commit-ack | Validated discovery candidate | Reported | Validated and represented by reportable finding: Fail-closed audit commits acknowledge queue admission rather than durable recording |
| Candidate disposition: focused-dry-run-c2s-generic-deny | Validated discovery candidate | Reported | Validated and represented by reportable finding: Dry-run forwards policy-denied client requests outside tools/call |
| Candidate disposition: focused-dry-run-s2c-generic-deny | Validated discovery candidate | Reported | Validated and represented by reportable finding: Dry-run forwards policy-denied server and MRTR requests to the client |
| Candidate disposition: focused-dry-run-tools-list-parse | Validated discovery candidate | Reported | Validated and represented by reportable finding: Malformed tools/list pages bypass first-seen verification in dry-run |
| Candidate disposition: focused-trajectory-cancel-race | Validated discovery candidate | Reported | Validated and represented by reportable finding: Cancellation can clear unresolved trajectory effects before the cancelled call finishes |
| Candidate disposition: focused-launch-hash-toctou | Validated discovery candidate | Reported | Validated and represented by reportable finding: Hash-pinned workloads are reopened by pathname after final verification |
| Candidate disposition: focused-unsupported-os-sandbox-fallback | Validated discovery candidate | Not applicable | Not applicable to the documented supported Linux, macOS, and Windows deployment contract; the fallback is visibly reported. |
| Candidate disposition: focused-runtime-windows-sandbox-staging-race | Validated discovery candidate | Rejected | Duplicate of the validated Windows Sandbox staging race finding. |
| Candidate disposition: focused-remote-container-context | Validated discovery candidate | Rejected | Rejected: no attacker-controlled path to a working remote same-path deployment was established under the trusted engine-configuration boundary. |
| Candidate disposition: focused-quickstart-ambient-env-dry-run | Validated discovery candidate | Reported | Validated and represented by reportable finding: Quick-start dry-run exposes the full parent environment to an unsandboxed server |
| Candidate disposition: focused-policygen-case-c-allowed | Validated discovery candidate | Reported | Validated and represented by reportable finding: Generated Case-C tools with unproven capabilities are allowed by default |
| Candidate disposition: focused-inspector-unbounded-input | Validated discovery candidate | Reported | Validated and represented by reportable finding: Inspector and policy generation process untrusted files without aggregate size limits |
| Candidate disposition: focused-engine-cleanup-unconfirmed | Validated discovery candidate | Reported | Validated and represented by reportable finding: Engine-backed cleanup reports success without confirming container or VM removal |
| Candidate disposition: focused-appcontainer-stale-dacl | Validated discovery candidate | Reported | Validated and represented by reportable finding: A reused AppContainer SID can inherit stale filesystem grants after abnormal cleanup |
| Candidate disposition: focused-containerize-source-toctou | Validated discovery candidate | Reported | Validated and represented by reportable finding: Containerize source staging can follow an attacker-swapped link outside the source tree |
| Candidate disposition: focused-tools-list-amplification | Validated discovery candidate | Reported | Validated and represented by reportable finding: tools/list collision diagnostics permit quadratic memory amplification |
