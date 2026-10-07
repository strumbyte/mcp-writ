# Security Review: mcp-writ

## Scope

Standard static security scan of the complete Git revision aa8fab4d94bd97be4fde8a416f42d8cda3fdd125 (305 tracked files).

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_65dbda789be9b0b19077db239957e3dbd0dc4ebb27a4c2904b4871cc14eeba1c
- Revision: aa8fab4d94bd97be4fde8a416f42d8cda3fdd125
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: Rust CLI, runtime, Warden, Auditor, verifier, policy, path, container, and static-analysis source, Cargo manifests and lockfile, repository documentation and policy examples, GitHub Actions workflows and release guidance

Limitations and exclusions:
- No live macOS, Linux, Windows, container, or MCP exploit reproduction was performed.
- Downstream URL and file-URL behavior varies by the selected MCP server runtime.
- A four-agent runtime cap reduced parallelism but did not reduce planned coverage.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 6 |
| Severity mix | high: 2, medium: 4 |
| Confidence mix | high: 6 |
| Coverage | partial |
| Validation mode | independent baseline, architecture mapping, focused static source traces, and parent revalidation |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

mcp-writ is a local Rust security wrapper that binds a materialized policy to one stdio MCP server, launches it through a platform-specific or container boundary, and audits bidirectional JSON-RPC before forwarding.

### Assets

- Bound policy and server code identity
- MCP tool definitions, arguments, results, and request correlation state
- Parent environment values and child filesystem/network/process authority
- Audit logs, launch reports, container build contexts, and release artifacts

### Trust Boundaries

- Untrusted MCP client traffic crosses Auditor before reaching the child server.
- A malicious child server controls stdout responses and advertised tool definitions before Auditor emits them to the client.
- Policy and operator configuration cross into Warden, Auditor, verifier, and container-engine controls.
- Native OS and OCI boundaries provide different filesystem, network, process, and reporting guarantees.

### Attacker Capabilities

- An MCP peer can send arbitrary bounded JSON-RPC frames, IDs, methods, arguments, tool definitions, and results.
- A malicious workload can exercise authority actually granted by the selected OS or container boundary.
- Operator-controlled policy, CLI, environment, image, and release inputs are trusted configuration rather than remote attacker capabilities.

### Security Objectives

- Verify, filter, and correlate every protocol message before crossing the client/server boundary.
- Authorize the same canonical filesystem or network object that the downstream server will consume.
- Bind the policy and executable identity before spawn and report weaker or degraded enforcement accurately.
- Bound attacker-controlled protocol state and fail closed when a required audit or verification control is unavailable.

### Assumptions

- No user security context, authoritative knowledge base, supplied threat model, or applicable SECURITY.md was available.
- Dry-run and explicit sandbox-skip modes are documented operator choices and are not treated as silent sandbox failures.
- The source explicitly retains a final hash-to-exec race and treats guest enforcement reports as guest-self-reported.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [A PATH-shadowed `sandbox-exec` can disable the macOS sandbox](#finding-1) | high | high | inline below |
| [A noncanonical URL can bypass host denies and reach internal services](#finding-2) | high | high | inline below |
| [A remote file URL can pass as a local path and trigger Windows UNC access](#finding-3) | medium | high | inline below |
| [A numerically aliased response can bypass `tools/list` verification](#finding-4) | medium | high | inline below |
| [A child exit can leave sandboxed descendants running after the session ends](#finding-5) | medium | high | inline below |
| [A renamed interpreter can execute code outside required identity pins](#finding-6) | medium | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] A PATH-shadowed `sandbox-exec` can disable the macOS sandbox

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Both macOS spawn paths use a bare helper name, restricted environment construction preserves the parent PATH, and successful process startup is accepted after only a liveness probe. |
| Category | untrusted-search-path |
| CWE | CWE-426 |
| Affected lines | src/warden/mod.rs:470, src/warden/env.rs:49-53, src/warden/macos_sandbox.rs:755-776, src/warden/macos_sandbox.rs:714-730 |

#### Summary

The normal macOS launch path invokes the security-enforcement helper by the bare name `sandbox-exec`. A writable directory placed before `/usr/bin` in the parent `PATH` can supply a replacement that ignores the generated SBPL profile and executes the verified workload unsandboxed.

#### Root Cause

The violated invariant is that the OS enforcement helper must be a trusted immutable executable. The macOS Warden constructs `Command` with a bare helper name, does not pin `/usr/bin/sandbox-exec`, and accepts the selected process based on liveness. A project-controlled PATH entry can therefore replace the mechanism that is supposed to create the sandbox.

**The enforcing helper is resolved by name** — `src/warden/mod.rs:470-471`

Normal asynchronous launches pass a bare program name to the OS process launcher, so helper selection depends on PATH rather than a trusted system object.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
```

**Environment restriction retains the parent PATH** — `src/warden/env.rs:49-53`

Even policies that restrict the workload environment preserve the inherited PATH; no trusted helper search path is constructed for the sandbox launcher.

```rust
fn restricted_base_env(allowed_names: &[String]) -> Vec<(OsString, OsString)> {
    let mut pairs = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        pairs.push((OsString::from("PATH"), path));
    }
```

**A replacement receives the profile and workload command** — `src/warden/mod.rs:470-495`

The shadow helper receives everything required to launch the target itself and can simply skip applying the `-p` profile.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through
            // bash — `exec -a` is a bash builtin, while /bin/sh may
            // resolve (via /var/select/sh) to a shell that lacks it. `-p`
            // keeps the wrapper in privileged mode: $ENV/$BASH_ENV are
            // not read, exported functions are not imported, and
            // SHELLOPTS/BASHOPTS/CDPATH/GLOBIGNORE from the environment
            // are ignored — a hostile spawn environment cannot reshape
            // the launch. `builtin` pins the exec call to the builtin as
            // well, so no inherited function name can intercept it.
            match program {
                Some(p) if p != Path::new(command) => {
                    cmd.arg("/bin/bash")
                        .arg("-p")
                        .arg("-c")
                        .arg("builtin exec -a \"$0\" \"$@\"")
                        .arg(command)
                        .arg(p)
                        .args(args);
                }
                _ => {
                    cmd.arg(command).args(args);
                }
            }
```

**A long-running replacement passes the post-spawn check** — `src/warden/macos_sandbox.rs:755-776`

The host verifies only that the selected process survives for 150 ms; a malicious shim that launches the workload and remains alive satisfies this check.

```rust
/// Total window [`initial_exit_check`] observes. A `sandbox-exec`
/// startup failure exits in single-digit milliseconds; the window
/// bounds the check without adding noticeable latency to a healthy
/// launch.
const INITIAL_EXIT_WINDOW: Duration = Duration::from_millis(150);
/// Poll granularity inside the window.
const INITIAL_EXIT_POLL: Duration = Duration::from_millis(10);

/// Bounded post-spawn liveness probe: polls `try_wait` until the child
/// exits or [`INITIAL_EXIT_WINDOW`] elapses. This is the only way to
/// catch a `sandbox-exec` startup rejection — `spawn()` succeeding only
/// proves the binary ran, and the child's stderr is the workload's own
/// channel, never parsed as evidence. Awaits between polls so the spawn
/// path never holds a runtime worker thread for the window.
pub(super) async fn initial_exit_check(child: &mut tokio::process::Child) -> SpawnLiveness {
    let deadline = Instant::now() + INITIAL_EXIT_WINDOW;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return SpawnLiveness::Exited(status),
            Ok(None) if Instant::now() >= deadline => return SpawnLiveness::Running,
            Ok(None) => tokio::time::sleep(INITIAL_EXIT_POLL).await,
            Err(_) => return SpawnLiveness::PollFailed,
```

#### Validation

The launch selects `sandbox-exec` through PATH, supplies it the target command, and performs no helper identity verification.

Validation method: static source trace

**The enforcing helper is resolved by name** — `src/warden/mod.rs:470-471`

Normal asynchronous launches pass a bare program name to the OS process launcher, so helper selection depends on PATH rather than a trusted system object.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
```

**Environment restriction retains the parent PATH** — `src/warden/env.rs:49-53`

Even policies that restrict the workload environment preserve the inherited PATH; no trusted helper search path is constructed for the sandbox launcher.

```rust
fn restricted_base_env(allowed_names: &[String]) -> Vec<(OsString, OsString)> {
    let mut pairs = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        pairs.push((OsString::from("PATH"), path));
    }
```

**A replacement receives the profile and workload command** — `src/warden/mod.rs:470-495`

The shadow helper receives everything required to launch the target itself and can simply skip applying the `-p` profile.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through
            // bash — `exec -a` is a bash builtin, while /bin/sh may
            // resolve (via /var/select/sh) to a shell that lacks it. `-p`
            // keeps the wrapper in privileged mode: $ENV/$BASH_ENV are
            // not read, exported functions are not imported, and
            // SHELLOPTS/BASHOPTS/CDPATH/GLOBIGNORE from the environment
            // are ignored — a hostile spawn environment cannot reshape
            // the launch. `builtin` pins the exec call to the builtin as
            // well, so no inherited function name can intercept it.
            match program {
                Some(p) if p != Path::new(command) => {
                    cmd.arg("/bin/bash")
                        .arg("-p")
                        .arg("-c")
                        .arg("builtin exec -a \"$0\" \"$@\"")
                        .arg(command)
                        .arg(p)
                        .args(args);
                }
                _ => {
                    cmd.arg(command).args(args);
                }
            }
```

**A long-running replacement passes the post-spawn check** — `src/warden/macos_sandbox.rs:755-776`

The host verifies only that the selected process survives for 150 ms; a malicious shim that launches the workload and remains alive satisfies this check.

```rust
/// Total window [`initial_exit_check`] observes. A `sandbox-exec`
/// startup failure exits in single-digit milliseconds; the window
/// bounds the check without adding noticeable latency to a healthy
/// launch.
const INITIAL_EXIT_WINDOW: Duration = Duration::from_millis(150);
/// Poll granularity inside the window.
const INITIAL_EXIT_POLL: Duration = Duration::from_millis(10);

/// Bounded post-spawn liveness probe: polls `try_wait` until the child
/// exits or [`INITIAL_EXIT_WINDOW`] elapses. This is the only way to
/// catch a `sandbox-exec` startup rejection — `spawn()` succeeding only
/// proves the binary ran, and the child's stderr is the workload's own
/// channel, never parsed as evidence. Awaits between polls so the spawn
/// path never holds a runtime worker thread for the window.
pub(super) async fn initial_exit_check(child: &mut tokio::process::Child) -> SpawnLiveness {
    let deadline = Instant::now() + INITIAL_EXIT_WINDOW;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return SpawnLiveness::Exited(status),
            Ok(None) if Instant::now() >= deadline => return SpawnLiveness::Running,
            Ok(None) => tokio::time::sleep(INITIAL_EXIT_POLL).await,
            Err(_) => return SpawnLiveness::PollFailed,
```

Assertions:
- A writable earlier PATH entry can replace the fixed-name helper.
- The replacement can ignore SBPL and execute the workload directly.
- Remaining alive beyond the liveness window is sufficient for the launch path to continue.

Counterevidence and remaining uncertainty:
- A conventional macOS system PATH places `/usr/bin` before user-writable directories.
- The helper name is fixed and not selected by workload argv.

Limitations:
- Validation was static and was not executed on a macOS host.

#### Dataflow

project-controlled PATH -\> bare helper resolution -\> fake helper receives SBPL and workload argv -\> fake helper skips sandbox -\> unsandboxed workload

Attack steps:
- Place a shim named `sandbox-exec` in the first writable PATH directory.
- Have the operator launch the MCP server through normal macOS enforcement.
- The Warden executes the shim and supplies the target command.
- The shim runs the target directly and remains alive beyond 150 ms.

- **Source:** attacker-controlled executable in an earlier PATH directory

- **Sink:** security-critical helper process selected by `Command::new("sandbox-exec")`

- **Outcome:** workload runs outside the configured macOS sandbox

**The enforcing helper is resolved by name** — `src/warden/mod.rs:470-471`

Normal asynchronous launches pass a bare program name to the OS process launcher, so helper selection depends on PATH rather than a trusted system object.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
```

**Environment restriction retains the parent PATH** — `src/warden/env.rs:49-53`

Even policies that restrict the workload environment preserve the inherited PATH; no trusted helper search path is constructed for the sandbox launcher.

```rust
fn restricted_base_env(allowed_names: &[String]) -> Vec<(OsString, OsString)> {
    let mut pairs = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        pairs.push((OsString::from("PATH"), path));
    }
```

**A replacement receives the profile and workload command** — `src/warden/mod.rs:470-495`

The shadow helper receives everything required to launch the target itself and can simply skip applying the `-p` profile.

```rust
            let mut cmd = tokio::process::Command::new("sandbox-exec");
            cmd.arg("-p").arg(&sbpl).arg("--");
            // sandbox-exec re-execs the given path with argv[0] equal to
            // that path, so a distinct verified executable goes through
            // bash — `exec -a` is a bash builtin, while /bin/sh may
            // resolve (via /var/select/sh) to a shell that lacks it. `-p`
            // keeps the wrapper in privileged mode: $ENV/$BASH_ENV are
            // not read, exported functions are not imported, and
            // SHELLOPTS/BASHOPTS/CDPATH/GLOBIGNORE from the environment
            // are ignored — a hostile spawn environment cannot reshape
            // the launch. `builtin` pins the exec call to the builtin as
            // well, so no inherited function name can intercept it.
            match program {
                Some(p) if p != Path::new(command) => {
                    cmd.arg("/bin/bash")
                        .arg("-p")
                        .arg("-c")
                        .arg("builtin exec -a \"$0\" \"$@\"")
                        .arg(command)
                        .arg(p)
                        .args(args);
                }
                _ => {
                    cmd.arg(command).args(args);
                }
            }
```

**A long-running replacement passes the post-spawn check** — `src/warden/macos_sandbox.rs:755-776`

The host verifies only that the selected process survives for 150 ms; a malicious shim that launches the workload and remains alive satisfies this check.

```rust
/// Total window [`initial_exit_check`] observes. A `sandbox-exec`
/// startup failure exits in single-digit milliseconds; the window
/// bounds the check without adding noticeable latency to a healthy
/// launch.
const INITIAL_EXIT_WINDOW: Duration = Duration::from_millis(150);
/// Poll granularity inside the window.
const INITIAL_EXIT_POLL: Duration = Duration::from_millis(10);

/// Bounded post-spawn liveness probe: polls `try_wait` until the child
/// exits or [`INITIAL_EXIT_WINDOW`] elapses. This is the only way to
/// catch a `sandbox-exec` startup rejection — `spawn()` succeeding only
/// proves the binary ran, and the child's stderr is the workload's own
/// channel, never parsed as evidence. Awaits between polls so the spawn
/// path never holds a runtime worker thread for the window.
pub(super) async fn initial_exit_check(child: &mut tokio::process::Child) -> SpawnLiveness {
    let deadline = Instant::now() + INITIAL_EXIT_WINDOW;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return SpawnLiveness::Exited(status),
            Ok(None) if Instant::now() >= deadline => return SpawnLiveness::Running,
            Ok(None) => tokio::time::sleep(INITIAL_EXIT_POLL).await,
            Err(_) => return SpawnLiveness::PollFailed,
```

#### Reachability

The attacker needs file placement in a directory the launcher puts before `/usr/bin`; package runners that prepend project-local binary directories provide a realistic path without prior host code execution.

- **Attacker:** malicious local MCP package or same-user project contributor

- **Entry point:** normal macOS Warden launch

- **Outcome:** full inherited host authority instead of SBPL-constrained authority

Preconditions:
- The parent PATH searches an attacker-writable directory before `/usr/bin`.
- A fake executable named `sandbox-exec` is present there.
- The operator launches `mcp-writ` from that environment.

Limitations:
- The exact PATH setup depends on how the operator launches the CLI.

#### Severity

**High** — The substituted helper runs before the intended sandbox exists and can give the workload the full filesystem and network authority of the `mcp-writ` process. Project-local package runners commonly prepend writable directories such as `node_modules/.bin` to `PATH`, making the prerequisite realistic for untrusted MCP packages.

Severity is lower only when the launcher guarantees a trusted immutable PATH ordering; it remains a complete sandbox bypass whenever an attacker can place the first matching executable.

Impact assessment:
- **Level:** high
- **Why:** Filesystem and network restrictions intended to contain untrusted workload code are completely absent.

Likelihood assessment:
- **Level:** medium
- **Why:** System PATH is normally safe, but project package runners frequently prepend writable local binary directories.

#### Remediation

Invoke `/usr/bin/sandbox-exec` by absolute path, validate that the opened helper is the expected root-owned non-writable system object, and fail the launch if helper identity cannot be established.

Tests:
- Prepend a temporary directory containing a fake `sandbox-exec` to PATH and assert that the fake helper is never invoked.
- Assert that a missing, replaced, or non-system `/usr/bin/sandbox-exec` fails the enforcing launch.

Preventive controls:
- Resolve security-critical OS helpers independently of user or project PATH.
- Bind helper identity before launch and record that identity in enforcement observations.

<a id="finding-2"></a>

### [2] A noncanonical URL can bypass host denies and reach internal services

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | The source trace shows partial canonicalization followed by string equality, and the original unmodified request is forwarded after authorization. The affected spellings have standard downstream URL interpretations. |
| Category | server-side-request-forgery |
| CWE | CWE-918, CWE-436 |
| Affected lines | src/policy/mod.rs:534-582, src/policy/host.rs:90-117, src/auditor/checker.rs:464-507, src/auditor/checker.rs:878-895, src/auditor/proxy_c2s.rs:542-560 |

#### Summary

Tool arguments are authorized with a partial textual host canonicalizer, then the original URL is forwarded to the MCP server. Whole-number and hexadecimal IPv4, wide final IPv4 components, equivalent IPv6 forms, and IDNA-equivalent names can resolve to a denied destination in downstream URL libraries while comparing unequal in the policy engine.

#### Root Cause

The violated invariant is that the host compared by policy must be the same network identity used by the downstream server. `extract_host_from_url()` performs a handwritten subset of URL parsing, `canonicalize_policy_host()` only folds restricted IPv4 components, and `host_matches()` compares strings. The authorized check therefore diverges from downstream parsers that canonicalize legacy IPv4, IPv6, or IDNA before connecting.

**Tool URLs enter host policy checks** — `src/auditor/checker.rs:464-507`

A caller-controlled URL is reduced to one host string and accepted unless that string matches a deny entry or fails an allow list.

```rust
    let mut hosts: Vec<String> = extracted.hosts.clone();
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => hosts.push(h),
            None => {
                if tool.network.is_some()
                    || !policy.network.outbound.denied_hosts.is_empty()
                    || policy.network.outbound.deny_all_others
                    || !policy.network.outbound.allowed.is_empty()
                {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "invalid or unparseable URL '{url}' in network-restricted tool"
                        ),
                    });
                }
            }
        }
    }

    for host in &hosts {
        for denied in &policy.network.outbound.denied_hosts {
            if host_matches(host, denied) {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' denied by global network policy"),
                });
            }
        }
        if policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty() {
            let allowed = policy
                .network
                .outbound
                .allowed
                .iter()
                .any(|a| host_matches(host, a));
            if !allowed {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' not in global outbound allow list"),
                });
            }
        }
```

**URL host extraction delegates to the partial canonicalizer** — `src/policy/host.rs:90-117`

The parser accepts bracketed IPv6 and percent-decoded domain text, but does not use a standards-compliant URL host representation before policy comparison.

```rust
    // IPv6 host: "[...]"
    let host_str = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        &host_port[1..end]
    } else {
        // Port is separated by ':' from the left for IPv4/hostname
        host_port.split(':').next()?
    };

    if host_str.is_empty() {
        return None;
    }

    // WHATWG URL Standard §4.3: Percent-decode the host
    let decoded = percent_decode_host(host_str)?;

    // Reject control characters, whitespace, and WHATWG-forbidden host
    // characters. ':' is structural inside a bracketed IPv6 literal.
    if decoded.chars().any(|c| {
        c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
            || (c == ':' && !host_port.starts_with('['))
    }) {
        return None;
    }

    Some(crate::policy::canonicalize_policy_host(&decoded))
```

**Legacy IPv4 parsing rejects valid wide components** — `src/policy/mod.rs:543-582`

Every component is capped at 255, making the one-part branch unable to accept a 32-bit IPv4 number and rejecting the wider final component permitted by legacy/WHATWG IPv4 parsing. IPv6 and IDNA are not canonicalized at all.

```rust
fn parse_ipv4_like(host: &str) -> Option<String> {
    if host.contains(':') || host.contains('/') {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_ipv4_component(part)?);
    }
    let addr = match nums.as_slice() {
        [a] => *a,
        [a, b] => (*a << 24) | *b,
        [a, b, c] => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] => (*a << 24) | (*b << 16) | (*c << 8) | *d,
        _ => return None,
    };
    Some(format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8) & 0xff,
        addr & 0xff
    ))
}

fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    let value = if let Some(hex) = part.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit()) {
        u32::from_str_radix(part, 8).ok()?
    } else {
        part.parse().ok()?
    };
    (value <= 255).then_some(value)
```

**Authorization compares canonicalized text** — `src/auditor/checker.rs:878-895`

The security decision is exact or suffix string matching, so distinct spellings that downstream networking resolves to the same address remain distinct to policy.

```rust
fn host_matches(host: &str, pattern: &str) -> bool {
    let host_lower = crate::policy::canonicalize_policy_host(&normalize_policy_host(host));
    let pat_lower = crate::policy::canonicalize_policy_host(pattern);

    if pat_lower == "*" {
        return true;
    }

    let pat_host = crate::policy::canonicalize_policy_host(&normalize_policy_host(&pat_lower));

    if host_lower == pat_host {
        return true;
    }
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return host_lower.ends_with(&with_dot);
    }
    false
```

**The original tool call is forwarded unchanged** — `src/auditor/proxy_c2s.rs:542-560`

A successful textual host check does not rewrite the URL; the original request line proceeds to the child, whose URL stack can resolve it differently.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

#### Validation

The request's host is checked in a weaker representation than the exact original URL later consumed by the tool server.

Validation method: static source trace and standards-based parser differential analysis

**Tool URLs enter host policy checks** — `src/auditor/checker.rs:464-507`

A caller-controlled URL is reduced to one host string and accepted unless that string matches a deny entry or fails an allow list.

```rust
    let mut hosts: Vec<String> = extracted.hosts.clone();
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => hosts.push(h),
            None => {
                if tool.network.is_some()
                    || !policy.network.outbound.denied_hosts.is_empty()
                    || policy.network.outbound.deny_all_others
                    || !policy.network.outbound.allowed.is_empty()
                {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "invalid or unparseable URL '{url}' in network-restricted tool"
                        ),
                    });
                }
            }
        }
    }

    for host in &hosts {
        for denied in &policy.network.outbound.denied_hosts {
            if host_matches(host, denied) {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' denied by global network policy"),
                });
            }
        }
        if policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty() {
            let allowed = policy
                .network
                .outbound
                .allowed
                .iter()
                .any(|a| host_matches(host, a));
            if !allowed {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' not in global outbound allow list"),
                });
            }
        }
```

**URL host extraction delegates to the partial canonicalizer** — `src/policy/host.rs:90-117`

The parser accepts bracketed IPv6 and percent-decoded domain text, but does not use a standards-compliant URL host representation before policy comparison.

```rust
    // IPv6 host: "[...]"
    let host_str = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        &host_port[1..end]
    } else {
        // Port is separated by ':' from the left for IPv4/hostname
        host_port.split(':').next()?
    };

    if host_str.is_empty() {
        return None;
    }

    // WHATWG URL Standard §4.3: Percent-decode the host
    let decoded = percent_decode_host(host_str)?;

    // Reject control characters, whitespace, and WHATWG-forbidden host
    // characters. ':' is structural inside a bracketed IPv6 literal.
    if decoded.chars().any(|c| {
        c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
            || (c == ':' && !host_port.starts_with('['))
    }) {
        return None;
    }

    Some(crate::policy::canonicalize_policy_host(&decoded))
```

**Legacy IPv4 parsing rejects valid wide components** — `src/policy/mod.rs:543-582`

Every component is capped at 255, making the one-part branch unable to accept a 32-bit IPv4 number and rejecting the wider final component permitted by legacy/WHATWG IPv4 parsing. IPv6 and IDNA are not canonicalized at all.

```rust
fn parse_ipv4_like(host: &str) -> Option<String> {
    if host.contains(':') || host.contains('/') {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_ipv4_component(part)?);
    }
    let addr = match nums.as_slice() {
        [a] => *a,
        [a, b] => (*a << 24) | *b,
        [a, b, c] => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] => (*a << 24) | (*b << 16) | (*c << 8) | *d,
        _ => return None,
    };
    Some(format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8) & 0xff,
        addr & 0xff
    ))
}

fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    let value = if let Some(hex) = part.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit()) {
        u32::from_str_radix(part, 8).ok()?
    } else {
        part.parse().ok()?
    };
    (value <= 255).then_some(value)
```

**Authorization compares canonicalized text** — `src/auditor/checker.rs:878-895`

The security decision is exact or suffix string matching, so distinct spellings that downstream networking resolves to the same address remain distinct to policy.

```rust
fn host_matches(host: &str, pattern: &str) -> bool {
    let host_lower = crate::policy::canonicalize_policy_host(&normalize_policy_host(host));
    let pat_lower = crate::policy::canonicalize_policy_host(pattern);

    if pat_lower == "*" {
        return true;
    }

    let pat_host = crate::policy::canonicalize_policy_host(&normalize_policy_host(&pat_lower));

    if host_lower == pat_host {
        return true;
    }
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return host_lower.ends_with(&with_dot);
    }
    false
```

**The original tool call is forwarded unchanged** — `src/auditor/proxy_c2s.rs:542-560`

A successful textual host check does not rewrite the URL; the original request line proceeds to the child, whose URL stack can resolve it differently.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

Assertions:
- `2130706433` and `0x7f000001` cannot pass the one-component canonicalization branch because each component is capped at 255.
- Equivalent expanded and compressed IPv6 spellings remain unrelated strings.
- The allowed request forwards its original URL, leaving the downstream parser to resolve the actual address.

Counterevidence and remaining uncertainty:
- ASCII whitespace, forbidden host characters, ports, userinfo, trailing root dots, and several dotted octal/hex forms are normalized or rejected.
- A deployment with independent OS-level deny-all networking blocks the connection even if Auditor authorizes it.

Limitations:
- No downstream MCP server was executed; exact accepted alternate spellings depend on that server's URL library.

#### Dataflow

tool argument URL -\> handwritten host extraction -\> partial canonicalization -\> string allow/deny match -\> original URL -\> downstream URL parser -\> internal connection

Attack steps:
- Select an allowed tool that accepts a URL.
- Supply an alternate IP or domain spelling such as a whole-number IPv4 or equivalent IPv6 form.
- Auditor compares the unnormalized spelling and authorizes the call.
- The child URL library canonicalizes the host and connects to the denied address.

- **Source:** caller-controlled URL or host argument

- **Sink:** network connection initiated by the allowed MCP tool

- **Outcome:** access to a destination denied by global or per-tool policy

**Tool URLs enter host policy checks** — `src/auditor/checker.rs:464-507`

A caller-controlled URL is reduced to one host string and accepted unless that string matches a deny entry or fails an allow list.

```rust
    let mut hosts: Vec<String> = extracted.hosts.clone();
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => hosts.push(h),
            None => {
                if tool.network.is_some()
                    || !policy.network.outbound.denied_hosts.is_empty()
                    || policy.network.outbound.deny_all_others
                    || !policy.network.outbound.allowed.is_empty()
                {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "invalid or unparseable URL '{url}' in network-restricted tool"
                        ),
                    });
                }
            }
        }
    }

    for host in &hosts {
        for denied in &policy.network.outbound.denied_hosts {
            if host_matches(host, denied) {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' denied by global network policy"),
                });
            }
        }
        if policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty() {
            let allowed = policy
                .network
                .outbound
                .allowed
                .iter()
                .any(|a| host_matches(host, a));
            if !allowed {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' not in global outbound allow list"),
                });
            }
        }
```

**URL host extraction delegates to the partial canonicalizer** — `src/policy/host.rs:90-117`

The parser accepts bracketed IPv6 and percent-decoded domain text, but does not use a standards-compliant URL host representation before policy comparison.

```rust
    // IPv6 host: "[...]"
    let host_str = if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        &host_port[1..end]
    } else {
        // Port is separated by ':' from the left for IPv4/hostname
        host_port.split(':').next()?
    };

    if host_str.is_empty() {
        return None;
    }

    // WHATWG URL Standard §4.3: Percent-decode the host
    let decoded = percent_decode_host(host_str)?;

    // Reject control characters, whitespace, and WHATWG-forbidden host
    // characters. ':' is structural inside a bracketed IPv6 literal.
    if decoded.chars().any(|c| {
        c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
            || (c == ':' && !host_port.starts_with('['))
    }) {
        return None;
    }

    Some(crate::policy::canonicalize_policy_host(&decoded))
```

**Legacy IPv4 parsing rejects valid wide components** — `src/policy/mod.rs:543-582`

Every component is capped at 255, making the one-part branch unable to accept a 32-bit IPv4 number and rejecting the wider final component permitted by legacy/WHATWG IPv4 parsing. IPv6 and IDNA are not canonicalized at all.

```rust
fn parse_ipv4_like(host: &str) -> Option<String> {
    if host.contains(':') || host.contains('/') {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_ipv4_component(part)?);
    }
    let addr = match nums.as_slice() {
        [a] => *a,
        [a, b] => (*a << 24) | *b,
        [a, b, c] => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] => (*a << 24) | (*b << 16) | (*c << 8) | *d,
        _ => return None,
    };
    Some(format!(
        "{}.{}.{}.{}",
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8) & 0xff,
        addr & 0xff
    ))
}

fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    let value = if let Some(hex) = part.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else if part.len() > 1 && part.starts_with('0') && part.bytes().all(|b| b.is_ascii_digit()) {
        u32::from_str_radix(part, 8).ok()?
    } else {
        part.parse().ok()?
    };
    (value <= 255).then_some(value)
```

**Authorization compares canonicalized text** — `src/auditor/checker.rs:878-895`

The security decision is exact or suffix string matching, so distinct spellings that downstream networking resolves to the same address remain distinct to policy.

```rust
fn host_matches(host: &str, pattern: &str) -> bool {
    let host_lower = crate::policy::canonicalize_policy_host(&normalize_policy_host(host));
    let pat_lower = crate::policy::canonicalize_policy_host(pattern);

    if pat_lower == "*" {
        return true;
    }

    let pat_host = crate::policy::canonicalize_policy_host(&normalize_policy_host(&pat_lower));

    if host_lower == pat_host {
        return true;
    }
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return host_lower.ends_with(&with_dot);
    }
    false
```

**The original tool call is forwarded unchanged** — `src/auditor/proxy_c2s.rs:542-560`

A successful textual host check does not rewrite the URL; the original request line proceeds to the child, whose URL stack can resolve it differently.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

#### Reachability

The attacker needs control of an argument to an allowed network-capable tool and a host spelling the tool's URL library canonicalizes more completely than Auditor.

- **Attacker:** prompt-injected or malicious MCP client input

- **Entry point:** `tools/call` URL or host argument

- **Outcome:** loopback or internal-service request under the tool's credentials

Preconditions:
- The selected tool accepts and connects to the supplied URL.
- The OS boundary permits the destination or relevant port.
- Auditor policy relies on a deny/allow host rule bypassed by the alternate spelling.

Limitations:
- Accepted alternate host syntax varies by downstream URL library.

#### Severity

**High** — A prompt-injected or malicious caller can redirect an allowed network-capable tool to loopback or internal services, potentially reading metadata, administration endpoints, or credentials. The path is practical wherever the OS boundary grants the relevant destination or port and relies on Auditor host checks.

Severity is lower in deployments with OS-level deny-all networking or destination filtering independent of Auditor, and higher when allowed tools can return internal service responses or mutate internal APIs.

Impact assessment:
- **Level:** high
- **Why:** The request can reach privileged local or internal HTTP services and expose data or perform state-changing actions.

Likelihood assessment:
- **Level:** medium
- **Why:** URL-taking MCP tools and downstream WHATWG-style parsers are common, but OS-level deny-all networking blocks some deployments.

#### Remediation

Parse and canonicalize URL authorities with the same standards-compliant semantics expected from supported tool runtimes; normalize IP literals through `IpAddr`, apply IDNA domain-to-ASCII, reject ambiguous legacy forms when equivalence cannot be guaranteed, and compare policy rules to the canonical network identity.

Tests:
- Deny `127.0.0.1` and assert rejection of `2130706433`, `0x7f000001`, `017700000001`, and other supported legacy spellings.
- Deny `::1` and assert rejection of expanded, compressed, and IPv4-mapped equivalents.
- Test IDNA and Unicode-equivalent hostnames against exact and wildcard deny rules.

Preventive controls:
- Centralize host parsing so extraction, policy matching, and forwarding share one canonical authority representation.
- Prefer fail-closed rejection of ambiguous host syntax to handwritten partial normalization.

<a id="finding-3"></a>

### [3] A remote file URL can pass as a local path and trigger Windows UNC access

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The source explicitly drops arbitrary authorities, excludes file URLs from network checks, and forwards the original argument. Windows file-URL-to-UNC interpretation is the remaining deployment precondition. |
| Category | path-authorization-parser-differential |
| CWE | CWE-22 |
| Affected lines | src/pathutil.rs:542-560, src/pathutil.rs:338-345, src/auditor/checker.rs:758-785, src/auditor/checker.rs:804-822, src/auditor/proxy_c2s.rs:542-560 |

#### Summary

`file_uri_to_fs_path()` discards every `file://` authority and authorizes only the remaining path, while `file:` values are excluded from network classification and the original request is forwarded unchanged. A downstream Windows runtime can interpret the same URI as a UNC resource on an attacker-selected host.

#### Root Cause

The violated invariant is that filesystem and network authorization must describe the same resource the server opens. `file_uri_to_fs_path()` strips arbitrary authorities as if they were local, `classify_target_string()` records only the resulting path, and the network classifier explicitly ignores `file:` URIs. The original URI survives into the child, where Windows semantics can restore the authority as a UNC host.

**Every file URL authority is discarded** — `src/pathutil.rs:542-560`

For `file://attacker/workspace/x`, the attacker-controlled authority is skipped and only `/workspace/x` remains for authorization; no check limits the authority to empty, localhost, or loopback.

```rust
pub fn file_uri_to_fs_path(uri: &str) -> Option<String> {
    let rest = strip_url_query_fragment(strip_file_scheme(uri.trim())?);
    // Align with WHATWG file URL path: backslash is a separator.
    let rest = rest.replace('\\', "/");
    if let Some(after) = rest.strip_prefix("//") {
        if after.starts_with('/') {
            return Some(after.to_string());
        }
        let slash = after.find('/').unwrap_or(after.len());
        let path = if slash < after.len() {
            &after[slash..]
        } else {
            ""
        };
        let path = strip_url_query_fragment(path);
        if path.is_empty() {
            return None;
        }
        return Some(path.to_string());
```

**File URLs are excluded from network policy** — `src/pathutil.rs:338-345`

The original URI is categorically excluded from network-target detection even when it names a remote authority.

```rust
/// True when `value` looks like a network target (URL or hostname).
///
/// `file:` URIs (including after bounded percent-decode) are filesystem
/// targets, not network hosts.
pub fn looks_like_network_target(value: &str) -> bool {
    if starts_with_file_scheme(value) {
        return false;
    }
```

**The authority-free value becomes a filesystem target** — `src/auditor/checker.rs:758-785`

Normalization turns the remote file URL into a local-looking path and returns before any host extraction, so only filesystem policy sees the value.

```rust
fn classify_target_string(key: &str, value: &str, out: &mut ExtractedTargets) {
    // Same Auditor-time normalize as overlay (bounded percent-decode + WHATWG
    // C0 strip + file: → path) so `file\t://` / `%66ile%0A://` become paths.
    let normalized = match crate::pathutil::normalize_fs_argument(value) {
        Ok(n) => n,
        Err(_) => {
            out.paths.push(value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        out.paths.push(normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(&normalized));
        } else {
            out.urls.push(value.to_string());
        }
        return;
```

**Authorization checks the wrong filesystem identity** — `src/auditor/checker.rs:804-822`

The filesystem policy resolves and compares the authority-free path, not the remote UNC object the downstream runtime may open.

```rust
fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    path: &str,
) -> Result<(), PolicyViolation> {
    let effective = match crate::pathutil::normalize_fs_argument(path) {
        Ok(normalized) => normalized,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("path '{path}' could not be normalized: {e}"),
            });
        }
    };
    let resolved =
        crate::pathutil::resolve_for_authorization(&effective).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("path '{path}' could not be resolved: {e}"),
        })?;
```

**The downstream server receives the original file URL** — `src/auditor/proxy_c2s.rs:542-560`

Authorization does not rewrite the argument, so a Windows runtime that converts file URLs to paths can recover the discarded authority and access `\\attacker\share\...`.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

#### Validation

The trace proves a policy/downstream representation mismatch for non-local file URL authorities.

Validation method: static source trace with platform-semantics review

**Every file URL authority is discarded** — `src/pathutil.rs:542-560`

For `file://attacker/workspace/x`, the attacker-controlled authority is skipped and only `/workspace/x` remains for authorization; no check limits the authority to empty, localhost, or loopback.

```rust
pub fn file_uri_to_fs_path(uri: &str) -> Option<String> {
    let rest = strip_url_query_fragment(strip_file_scheme(uri.trim())?);
    // Align with WHATWG file URL path: backslash is a separator.
    let rest = rest.replace('\\', "/");
    if let Some(after) = rest.strip_prefix("//") {
        if after.starts_with('/') {
            return Some(after.to_string());
        }
        let slash = after.find('/').unwrap_or(after.len());
        let path = if slash < after.len() {
            &after[slash..]
        } else {
            ""
        };
        let path = strip_url_query_fragment(path);
        if path.is_empty() {
            return None;
        }
        return Some(path.to_string());
```

**File URLs are excluded from network policy** — `src/pathutil.rs:338-345`

The original URI is categorically excluded from network-target detection even when it names a remote authority.

```rust
/// True when `value` looks like a network target (URL or hostname).
///
/// `file:` URIs (including after bounded percent-decode) are filesystem
/// targets, not network hosts.
pub fn looks_like_network_target(value: &str) -> bool {
    if starts_with_file_scheme(value) {
        return false;
    }
```

**The authority-free value becomes a filesystem target** — `src/auditor/checker.rs:758-785`

Normalization turns the remote file URL into a local-looking path and returns before any host extraction, so only filesystem policy sees the value.

```rust
fn classify_target_string(key: &str, value: &str, out: &mut ExtractedTargets) {
    // Same Auditor-time normalize as overlay (bounded percent-decode + WHATWG
    // C0 strip + file: → path) so `file\t://` / `%66ile%0A://` become paths.
    let normalized = match crate::pathutil::normalize_fs_argument(value) {
        Ok(n) => n,
        Err(_) => {
            out.paths.push(value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        out.paths.push(normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(&normalized));
        } else {
            out.urls.push(value.to_string());
        }
        return;
```

**Authorization checks the wrong filesystem identity** — `src/auditor/checker.rs:804-822`

The filesystem policy resolves and compares the authority-free path, not the remote UNC object the downstream runtime may open.

```rust
fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    path: &str,
) -> Result<(), PolicyViolation> {
    let effective = match crate::pathutil::normalize_fs_argument(path) {
        Ok(normalized) => normalized,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("path '{path}' could not be normalized: {e}"),
            });
        }
    };
    let resolved =
        crate::pathutil::resolve_for_authorization(&effective).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("path '{path}' could not be resolved: {e}"),
        })?;
```

**The downstream server receives the original file URL** — `src/auditor/proxy_c2s.rs:542-560`

Authorization does not rewrite the argument, so a Windows runtime that converts file URLs to paths can recover the discarded authority and access `\\attacker\share\...`.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

Assertions:
- `file://attacker/workspace/x` is reduced to `/workspace/x` before filesystem authorization.
- No network host check is applied to the discarded authority.
- The child receives the untouched URI and may interpret it as a Windows UNC path.

Counterevidence and remaining uncertainty:
- Some non-Windows runtimes reject non-local file URL authorities.
- Windows AppContainer networking or share ACLs can independently prevent a particular remote access.

Limitations:
- No Windows downstream tool was executed during validation.

#### Dataflow

file URL argument -\> authority discarded -\> local path authorization -\> original URI -\> Windows file-URL conversion -\> UNC access

Attack steps:
- Supply `file://attacker/share/path` in a filesystem-bearing argument.
- Auditor discards `attacker`, authorizes `/share/path`, and performs no host check.
- The original URI reaches the child.
- The child converts it to `\\attacker\share\path` and accesses the remote host.

- **Source:** caller-controlled non-local file URL

- **Sink:** downstream file open or write on a UNC resource

- **Outcome:** remote share access and possible SMB credential exposure outside network policy

**Every file URL authority is discarded** — `src/pathutil.rs:542-560`

For `file://attacker/workspace/x`, the attacker-controlled authority is skipped and only `/workspace/x` remains for authorization; no check limits the authority to empty, localhost, or loopback.

```rust
pub fn file_uri_to_fs_path(uri: &str) -> Option<String> {
    let rest = strip_url_query_fragment(strip_file_scheme(uri.trim())?);
    // Align with WHATWG file URL path: backslash is a separator.
    let rest = rest.replace('\\', "/");
    if let Some(after) = rest.strip_prefix("//") {
        if after.starts_with('/') {
            return Some(after.to_string());
        }
        let slash = after.find('/').unwrap_or(after.len());
        let path = if slash < after.len() {
            &after[slash..]
        } else {
            ""
        };
        let path = strip_url_query_fragment(path);
        if path.is_empty() {
            return None;
        }
        return Some(path.to_string());
```

**File URLs are excluded from network policy** — `src/pathutil.rs:338-345`

The original URI is categorically excluded from network-target detection even when it names a remote authority.

```rust
/// True when `value` looks like a network target (URL or hostname).
///
/// `file:` URIs (including after bounded percent-decode) are filesystem
/// targets, not network hosts.
pub fn looks_like_network_target(value: &str) -> bool {
    if starts_with_file_scheme(value) {
        return false;
    }
```

**The authority-free value becomes a filesystem target** — `src/auditor/checker.rs:758-785`

Normalization turns the remote file URL into a local-looking path and returns before any host extraction, so only filesystem policy sees the value.

```rust
fn classify_target_string(key: &str, value: &str, out: &mut ExtractedTargets) {
    // Same Auditor-time normalize as overlay (bounded percent-decode + WHATWG
    // C0 strip + file: → path) so `file\t://` / `%66ile%0A://` become paths.
    let normalized = match crate::pathutil::normalize_fs_argument(value) {
        Ok(n) => n,
        Err(_) => {
            out.paths.push(value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        out.paths.push(normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(&normalized));
        } else {
            out.urls.push(value.to_string());
        }
        return;
```

**Authorization checks the wrong filesystem identity** — `src/auditor/checker.rs:804-822`

The filesystem policy resolves and compares the authority-free path, not the remote UNC object the downstream runtime may open.

```rust
fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    path: &str,
) -> Result<(), PolicyViolation> {
    let effective = match crate::pathutil::normalize_fs_argument(path) {
        Ok(normalized) => normalized,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("path '{path}' could not be normalized: {e}"),
            });
        }
    };
    let resolved =
        crate::pathutil::resolve_for_authorization(&effective).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("path '{path}' could not be resolved: {e}"),
        })?;
```

**The downstream server receives the original file URL** — `src/auditor/proxy_c2s.rs:542-560`

Authorization does not rewrite the argument, so a Windows runtime that converts file URLs to paths can recover the discarded authority and access `\\attacker\share\...`.

```rust
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
```

#### Reachability

The vulnerable deployment is Windows with a tool that accepts file URLs, a filesystem rule matching the authority-free path, and OS networking that permits the UNC attempt.

- **Attacker:** MCP client controlling a file or URI argument

- **Entry point:** `tools/call` file URL field

- **Outcome:** outbound SMB or remote-share read/write under workload authority

Preconditions:
- The downstream tool converts non-local file URLs to Windows UNC paths.
- The stripped path matches an allowed filesystem rule.
- AppContainer or unsandboxed networking permits the remote access.

Limitations:
- Exact UNC behavior depends on the downstream runtime.

#### Severity

**Medium** — A caller can turn an allowed local-looking path into outbound SMB or remote-share access, bypassing both filesystem object identity and per-tool host policy. Impact depends on a Windows tool runtime accepting file URLs and OS networking permitting the connection.

Severity increases when the child can authenticate to remote shares or expose Windows credentials, and decreases when non-local file authorities are rejected downstream or the OS sandbox denies all network access.

Impact assessment:
- **Level:** medium
- **Why:** The call can access a remote share or initiate SMB authentication despite local-path and host restrictions.

Likelihood assessment:
- **Level:** medium
- **Why:** It requires Windows plus a file-URL-aware tool, but those are realistic supported conditions.

#### Remediation

Validate the file URL authority before path conversion: reject non-local authorities on platforms that do not support them, and on Windows either reject them or preserve a canonical UNC path and apply both filesystem and network policy to the actual host and share.

Tests:
- Assert that `file://evil/share/path` is rejected under a local-only filesystem policy.
- Cover percent-encoded, IPv4, IPv6, localhost, and direct UNC-equivalent authorities on Windows.
- Assert that accepted local file URLs resolve to the same canonical path used for authorization.

Preventive controls:
- Use a platform-aware file URL parser that returns authority and path as separate typed values.
- Never discard a parsed URI authority before both filesystem and network authorization are complete.

<a id="finding-4"></a>

### [4] A numerically aliased response can bypass `tools/list` verification

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | A complete static trace shows canonical correlation in `WireState`, raw-text comparison in `S2cListState`, and the resulting `ForwardRaw` sink. |
| Category | protocol-correlation-mismatch |
| CWE | CWE-436 |
| Affected lines | src/auditor/proxy_list_state.rs:73-79, src/auditor/proxy_tools_list.rs:187-211, src/auditor/proxy_tools_list.rs:234-237, src/auditor/proxy_s2c.rs:181-184 |

#### Summary

A malicious MCP server can answer an internally generated pagination request with a mathematically equivalent JSON number whose spelling matches the original client request. Wire correlation accepts the canonical numeric ID, but the `tools/list` state compares raw ID text, falls through to `ForwardRaw`, and emits an unverified tool page to the client.

#### Root Cause

The violated invariant is that every response recognized by canonical JSON-RPC correlation as an internal `tools/list` response must remain internal and pass the list verifier. `WireState` uses canonical `RpcId` values, but `S2cListState` stores the minted ID as decimal text and tests the response's raw spelling, allowing equivalent numeric spellings to disagree.

**Numeric JSON-RPC IDs are canonicalized** — `src/auditor/session.rs:56-67`

The peer-controlled numeric response ID is reduced to a canonical value, so `910001`, `910001.0`, and `9.10001e5` correlate to the same tracked request.

```rust
impl RpcId {
    pub fn parse_from_json(id: nojson::RawJsonValue<'_, '_>) -> Option<Self> {
        match id.kind() {
            nojson::JsonValueKind::Null => Some(Self::Null),
            nojson::JsonValueKind::Integer | nojson::JsonValueKind::Float => {
                Some(Self::Number(canonicalize_json_number(id.as_raw_str())))
            }
            nojson::JsonValueKind::String => id
                .to_unquoted_string_str()
                .ok()
                .map(|s| Self::String(s.into_owned())),
            _ => None,
```

**Internal list state compares raw ID spelling** — `src/auditor/proxy_list_state.rs:73-79`

The same response is classified against the internal list request using its original JSON spelling rather than the canonical `RpcId`, creating a parser-state disagreement.

```rust
    pub(super) fn is_internal_response(&self, raw_id: Option<&str>) -> bool {
        self.waiting_internal_id.is_some() && self.waiting_internal_id.as_deref() == raw_id
    }

    pub(super) fn expect_internal_response(&mut self, internal_id: u64) {
        self.waiting_internal_id = Some(internal_id.to_string());
    }
```

**The alias is no longer recognized as a list response** — `src/auditor/proxy_tools_list.rs:187-211`

After wire correlation consumes the internal request, the original client list ID is no longer pending and `answered_internal` is false under raw-text comparison. Without configured list hashes, the tool page is not recognized for verification.

```rust
    let is_tools_list_response = if let Some(id) = rpc_id {
        if matches!(id, RpcId::Null) {
            false
        } else {
            let mut pending = shared.pending_tools_list.lock().await;
            // Pending tools/list ids are consumed only by genuine
            // responses; a same-id server-initiated request must not
            // consume them. An envelope that already failed the wire
            // gate is flagged so the malformed-envelope check below
            // blocks it, without consuming the entry — in dry-run a
            // legitimate response can still resolve the listing.
            let tracked = if is_response && malformed_reason.is_none() {
                pending.remove(id)
            } else {
                has_result_or_error && pending.contains(id)
            };
            tracked || answered_internal
        }
    } else {
        false
    };

    let seems_tools_list = is_tools_list_response
        || (!shared.policy.tools_list_hashes.is_empty()
            && parsed_value.is_some_and(response_result_has_tools_field));
```

**Unrecognized list traffic is emitted unchanged** — `src/auditor/proxy_s2c.rs:181-184`

The supposedly impossible fallthrough writes the malicious server frame directly to the client, skipping list accumulation, filtering, and integrity verification.

```rust
        ListFlow::Handled => Ok(()),
        // Cannot happen for a list-tracked frame — defensive forward.
        ListFlow::ForwardRaw => write_client_frame(&shared.client_out, line).await,
    }
```

#### Validation

The trace confirms canonical numeric correlation, raw internal-ID comparison, removal of the original pending client ID, and the reachable raw-forward branch.

Validation method: static source trace

**Numeric JSON-RPC IDs are canonicalized** — `src/auditor/session.rs:56-67`

The peer-controlled numeric response ID is reduced to a canonical value, so `910001`, `910001.0`, and `9.10001e5` correlate to the same tracked request.

```rust
impl RpcId {
    pub fn parse_from_json(id: nojson::RawJsonValue<'_, '_>) -> Option<Self> {
        match id.kind() {
            nojson::JsonValueKind::Null => Some(Self::Null),
            nojson::JsonValueKind::Integer | nojson::JsonValueKind::Float => {
                Some(Self::Number(canonicalize_json_number(id.as_raw_str())))
            }
            nojson::JsonValueKind::String => id
                .to_unquoted_string_str()
                .ok()
                .map(|s| Self::String(s.into_owned())),
            _ => None,
```

**Internal list state compares raw ID spelling** — `src/auditor/proxy_list_state.rs:73-79`

The same response is classified against the internal list request using its original JSON spelling rather than the canonical `RpcId`, creating a parser-state disagreement.

```rust
    pub(super) fn is_internal_response(&self, raw_id: Option<&str>) -> bool {
        self.waiting_internal_id.is_some() && self.waiting_internal_id.as_deref() == raw_id
    }

    pub(super) fn expect_internal_response(&mut self, internal_id: u64) {
        self.waiting_internal_id = Some(internal_id.to_string());
    }
```

**The alias is no longer recognized as a list response** — `src/auditor/proxy_tools_list.rs:187-211`

After wire correlation consumes the internal request, the original client list ID is no longer pending and `answered_internal` is false under raw-text comparison. Without configured list hashes, the tool page is not recognized for verification.

```rust
    let is_tools_list_response = if let Some(id) = rpc_id {
        if matches!(id, RpcId::Null) {
            false
        } else {
            let mut pending = shared.pending_tools_list.lock().await;
            // Pending tools/list ids are consumed only by genuine
            // responses; a same-id server-initiated request must not
            // consume them. An envelope that already failed the wire
            // gate is flagged so the malformed-envelope check below
            // blocks it, without consuming the entry — in dry-run a
            // legitimate response can still resolve the listing.
            let tracked = if is_response && malformed_reason.is_none() {
                pending.remove(id)
            } else {
                has_result_or_error && pending.contains(id)
            };
            tracked || answered_internal
        }
    } else {
        false
    };

    let seems_tools_list = is_tools_list_response
        || (!shared.policy.tools_list_hashes.is_empty()
            && parsed_value.is_some_and(response_result_has_tools_field));
```

**Unrecognized list traffic is emitted unchanged** — `src/auditor/proxy_s2c.rs:181-184`

The supposedly impossible fallthrough writes the malicious server frame directly to the client, skipping list accumulation, filtering, and integrity verification.

```rust
        ListFlow::Handled => Ok(()),
        // Cannot happen for a list-tracked frame — defensive forward.
        ListFlow::ForwardRaw => write_client_frame(&shared.client_out, line).await,
    }
```

Assertions:
- A response ID such as `910001.0` canonically answers internally minted ID `910001`.
- The same response fails the raw string equality test against `"910001"`.
- When no `tools_list_hashes` fallback applies, the frame reaches `ForwardRaw` and is written unchanged to the client.

Counterevidence and remaining uncertainty:
- The original client request must use a numeric spelling mathematically equivalent to the predictable internal ID for the forwarded response to correlate at the client.
- Subsequent `tools/call` requests still pass through normal policy checks even if the client saw an unfiltered definition.

Limitations:
- Validation was static; no live client/server reproduction was run.

#### Dataflow

client `tools/list` ID -\> canonical `RpcId` tracking -\> internal decimal ID -\> aliased server response -\> raw internal-ID mismatch -\> `ForwardRaw` -\> client

Attack steps:
- Observe a client `tools/list` request using an aliased ID such as `910001.0`.
- Return a first page with `nextCursor` so the proxy emits internal request ID `910001`.
- Answer the internal request with an equivalent spelling such as `9.10001e5` and attacker-controlled tools.
- The proxy forwards that page raw; the client correlates it to its original request.

- **Source:** server-controlled response ID and `result.tools` page

- **Sink:** `write_client_frame()` on the `ForwardRaw` branch

- **Outcome:** the client receives unfiltered or integrity-mismatched tool definitions

Transformations:
- numeric ID canonicalization for wire state
- raw-string comparison for list state

**Numeric JSON-RPC IDs are canonicalized** — `src/auditor/session.rs:56-67`

The peer-controlled numeric response ID is reduced to a canonical value, so `910001`, `910001.0`, and `9.10001e5` correlate to the same tracked request.

```rust
impl RpcId {
    pub fn parse_from_json(id: nojson::RawJsonValue<'_, '_>) -> Option<Self> {
        match id.kind() {
            nojson::JsonValueKind::Null => Some(Self::Null),
            nojson::JsonValueKind::Integer | nojson::JsonValueKind::Float => {
                Some(Self::Number(canonicalize_json_number(id.as_raw_str())))
            }
            nojson::JsonValueKind::String => id
                .to_unquoted_string_str()
                .ok()
                .map(|s| Self::String(s.into_owned())),
            _ => None,
```

**Internal list state compares raw ID spelling** — `src/auditor/proxy_list_state.rs:73-79`

The same response is classified against the internal list request using its original JSON spelling rather than the canonical `RpcId`, creating a parser-state disagreement.

```rust
    pub(super) fn is_internal_response(&self, raw_id: Option<&str>) -> bool {
        self.waiting_internal_id.is_some() && self.waiting_internal_id.as_deref() == raw_id
    }

    pub(super) fn expect_internal_response(&mut self, internal_id: u64) {
        self.waiting_internal_id = Some(internal_id.to_string());
    }
```

**The alias is no longer recognized as a list response** — `src/auditor/proxy_tools_list.rs:187-211`

After wire correlation consumes the internal request, the original client list ID is no longer pending and `answered_internal` is false under raw-text comparison. Without configured list hashes, the tool page is not recognized for verification.

```rust
    let is_tools_list_response = if let Some(id) = rpc_id {
        if matches!(id, RpcId::Null) {
            false
        } else {
            let mut pending = shared.pending_tools_list.lock().await;
            // Pending tools/list ids are consumed only by genuine
            // responses; a same-id server-initiated request must not
            // consume them. An envelope that already failed the wire
            // gate is flagged so the malformed-envelope check below
            // blocks it, without consuming the entry — in dry-run a
            // legitimate response can still resolve the listing.
            let tracked = if is_response && malformed_reason.is_none() {
                pending.remove(id)
            } else {
                has_result_or_error && pending.contains(id)
            };
            tracked || answered_internal
        }
    } else {
        false
    };

    let seems_tools_list = is_tools_list_response
        || (!shared.policy.tools_list_hashes.is_empty()
            && parsed_value.is_some_and(response_result_has_tools_field));
```

**Unrecognized list traffic is emitted unchanged** — `src/auditor/proxy_s2c.rs:181-184`

The supposedly impossible fallthrough writes the malicious server frame directly to the client, skipping list accumulation, filtering, and integrity verification.

```rust
        ListFlow::Handled => Ok(()),
        // Cannot happen for a list-tracked frame — defensive forward.
        ListFlow::ForwardRaw => write_client_frame(&shared.client_out, line).await,
    }
```

#### Reachability

The server is already an untrusted stdio peer. Exploitation additionally depends on the client using a numeric spelling equivalent to the predictable internal counter and accepting equivalent numeric response IDs.

- **Attacker:** malicious or compromised MCP server

- **Entry point:** paginated `tools/list` response

- **Outcome:** unverified tool descriptions and schemas become visible to the client

Preconditions:
- The victim client request ID is numerically equivalent to the current internal ID.
- The server returns a cursor to trigger an internal follow-up.
- No configured `tools_list_hashes` fallback recognizes the response.
- The client correlates numerically equivalent JSON number spellings.

Limitations:
- No supported client implementation was tested for the exact numeric alias sequence.

#### Severity

**Medium** — The bypass can expose unfiltered or integrity-mismatched tool definitions to the client, including attacker-controlled descriptions and schemas. Exploitation requires an original client request ID that is numerically equivalent to the predictable internal ID, which limits likelihood.

Severity would increase if a supported client predictably uses the internal numeric range or if downstream clients act on duplicate/aliased responses without additional confirmation; it would decrease if all supported clients reject such numeric ID spellings.

Impact assessment:
- **Level:** medium
- **Why:** The server can bypass list filtering and integrity checks, influencing client-visible tool metadata; later tool calls remain policy-gated.

Likelihood assessment:
- **Level:** low
- **Why:** The numeric-ID collision and client correlation behavior are uncommon and not controlled solely by the malicious server.

#### Remediation

Represent `waiting_internal_id` as canonical `RpcId` and carry the already trusted internal-response fact into `handle_tools_list_response`; an internal response must never be eligible for `ForwardRaw`.

Tests:
- Start paginated `tools/list` with client ID `910001.0`, answer the internal `910001` request as `9.10001e5`, and assert that the frame is never forwarded raw.
- Exercise integer, decimal, and exponent aliases for internal IDs with and without `tools_list_hashes` configured.

Preventive controls:
- Use one canonical ID type for wire correlation and every protocol sub-state machine.
- Make `ForwardRaw` reject any response already classified as internal by `WireState`.

<a id="finding-5"></a>

### [5] A child exit can leave sandboxed descendants running after the session ends

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The direct-child wait, natural-exit branch, process-group-only cleanup, and Tokio 1.53.1 post-completion `id() == None` behavior form a complete source-backed lifecycle trace. |
| Category | incomplete-descendant-containment |
| CWE | CWE-653 |
| Affected lines | src/warden/child.rs:173-189, src/runtime/wait.rs:164-172, src/warden/child.rs:250-264, src/warden/child.rs:268-287, src/warden/macos_sandbox.rs:203-210 |

#### Summary

Unix launches create a process group, but the natural-exit path waits only for the direct child and then drops a completed Tokio child. Because its PID is no longer available, `Drop` cannot signal the original group, allowing forked descendants to keep running with the workload's granted filesystem and network authority.

#### Root Cause

The violated invariant is that ending the MCP session must revoke the lifetime of every workload process. Unix containment records no durable group or descendant-tree handle. `wait_for_natural_exit()` consumes the direct child first, the runtime finalizes, and `Drop` conditionally derives the group ID from a child handle whose ID is gone after completion.

**macOS workloads may fork descendants** — `src/warden/macos_sandbox.rs:203-210`

Every macOS profile permits the workload to create a descendant that inherits the same sandbox grants.

```rust
    // --- Essential process operations ---
    for op in [
        "process-fork",
        "process-exec",
        "signal (target self)",
        "process-info* (target same-sandbox)",
        "sysctl-read",
    ] {
```

**Natural exit waits only for the direct child** — `src/warden/child.rs:173-189`

This branch reaps the group leader without first killing or enumerating any descendants.

```rust
    /// Wait for the child to exit without sending SIGKILL first.
    ///
    /// Use this whenever the caller must observe the child's own lifetime
    /// (`mcp-writ run` / `mcp-secure-runner` select, self-test EACCES/SIGSYS,
    /// SIGTERM/SIGINT grace). [`Self::wait`] tears down the process group and
    /// must not be polled as "wait until the MCP server exits".
    pub async fn wait_for_natural_exit(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.wait())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
```

**The host finalizes immediately after the leader exits** — `src/runtime/wait.rs:164-172`

The direct child's exit wins the session select and proceeds to finalization even if descendants are still alive.

```rust
        status = child.wait_for_natural_exit() => {
            match status {
                Ok(s) => {
                    let code = observed_exit_code(&s);
                    if let Some(label) = labels.child_exited {
                        tracing::info!("{label} with code {code}");
                    }
                    audit_logger.shutdown().await;
                    drop(child);
```

**Drop can signal the group only while a PID remains** — `src/warden/child.rs:250-264`

Tokio 1.53.1 returns no ID after a child has been polled to completion, so the natural-exit path skips the negative-PID group signal.

```rust
impl Drop for RunningChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
        }
        match &mut self.inner {
            RunningChildInner::Tokio(child) => {
                let _ = child.start_kill();
            }
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let _ = child.kill();
            }
        }
```

**Unix containment tracks only the original process group** — `src/warden/child.rs:268-287`

No cgroup, subreaper, or retained PGID owns the descendant tree; all cleanup depends on recovering the original leader PID.

```rust
pub(super) fn apply_unix_process_group(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd;
}

pub(super) fn apply_unix_process_group_tokio(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let _ = cmd;
}

#[cfg(unix)]
fn kill_unix_process_group(pid: u32) {
    let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
```

#### Validation

A workload can fork, let its leader exit, and retain a descendant because natural completion never reaches group teardown with a usable PGID.

Validation method: static lifecycle trace with pinned dependency API verification

**macOS workloads may fork descendants** — `src/warden/macos_sandbox.rs:203-210`

Every macOS profile permits the workload to create a descendant that inherits the same sandbox grants.

```rust
    // --- Essential process operations ---
    for op in [
        "process-fork",
        "process-exec",
        "signal (target self)",
        "process-info* (target same-sandbox)",
        "sysctl-read",
    ] {
```

**Natural exit waits only for the direct child** — `src/warden/child.rs:173-189`

This branch reaps the group leader without first killing or enumerating any descendants.

```rust
    /// Wait for the child to exit without sending SIGKILL first.
    ///
    /// Use this whenever the caller must observe the child's own lifetime
    /// (`mcp-writ run` / `mcp-secure-runner` select, self-test EACCES/SIGSYS,
    /// SIGTERM/SIGINT grace). [`Self::wait`] tears down the process group and
    /// must not be polled as "wait until the MCP server exits".
    pub async fn wait_for_natural_exit(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.wait())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
```

**The host finalizes immediately after the leader exits** — `src/runtime/wait.rs:164-172`

The direct child's exit wins the session select and proceeds to finalization even if descendants are still alive.

```rust
        status = child.wait_for_natural_exit() => {
            match status {
                Ok(s) => {
                    let code = observed_exit_code(&s);
                    if let Some(label) = labels.child_exited {
                        tracing::info!("{label} with code {code}");
                    }
                    audit_logger.shutdown().await;
                    drop(child);
```

**Drop can signal the group only while a PID remains** — `src/warden/child.rs:250-264`

Tokio 1.53.1 returns no ID after a child has been polled to completion, so the natural-exit path skips the negative-PID group signal.

```rust
impl Drop for RunningChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
        }
        match &mut self.inner {
            RunningChildInner::Tokio(child) => {
                let _ = child.start_kill();
            }
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let _ = child.kill();
            }
        }
```

**Unix containment tracks only the original process group** — `src/warden/child.rs:268-287`

No cgroup, subreaper, or retained PGID owns the descendant tree; all cleanup depends on recovering the original leader PID.

```rust
pub(super) fn apply_unix_process_group(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd;
}

pub(super) fn apply_unix_process_group_tokio(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let _ = cmd;
}

#[cfg(unix)]
fn kill_unix_process_group(pid: u32) {
    let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
```

Assertions:
- The natural-exit branch reaps only the direct child.
- Tokio 1.53.1 returns `None` from `Child::id()` after completion.
- Every Unix group signal derives its target from the current direct-child ID, and no descendant owner is retained.

Counterevidence and remaining uncertainty:
- Explicit kill paths signal descendants that remain in the original process group while the leader PID is still available.
- Survivors inherit OS sandbox restrictions.
- Linux exploitability depends on process-creation syscalls permitted by policy.

Limitations:
- No macOS or Linux process-tree reproduction was run.

#### Dataflow

sandboxed workload -\> forked descendant -\> direct child exit -\> natural wait completes -\> completed child has no ID -\> drop skips group kill -\> descendant persists

Attack steps:
- Fork a background descendant that keeps performing an allowed action.
- Exit the direct child cleanly.
- The runtime finalizes on direct-child completion.
- Drop cannot recover the completed child's PID and never signals the group.

- **Source:** workload-controlled process creation and parent exit

- **Sink:** untracked descendant retaining inherited sandbox grants

- **Outcome:** filesystem or network activity continues after the MCP session is reported finished

**macOS workloads may fork descendants** — `src/warden/macos_sandbox.rs:203-210`

Every macOS profile permits the workload to create a descendant that inherits the same sandbox grants.

```rust
    // --- Essential process operations ---
    for op in [
        "process-fork",
        "process-exec",
        "signal (target self)",
        "process-info* (target same-sandbox)",
        "sysctl-read",
    ] {
```

**Natural exit waits only for the direct child** — `src/warden/child.rs:173-189`

This branch reaps the group leader without first killing or enumerating any descendants.

```rust
    /// Wait for the child to exit without sending SIGKILL first.
    ///
    /// Use this whenever the caller must observe the child's own lifetime
    /// (`mcp-writ run` / `mcp-secure-runner` select, self-test EACCES/SIGSYS,
    /// SIGTERM/SIGINT grace). [`Self::wait`] tears down the process group and
    /// must not be polled as "wait until the MCP server exits".
    pub async fn wait_for_natural_exit(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match &mut self.inner {
            RunningChildInner::Tokio(child) => child.wait().await,
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let c = child.clone();
                tokio::task::spawn_blocking(move || c.wait())
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            }
        }
```

**The host finalizes immediately after the leader exits** — `src/runtime/wait.rs:164-172`

The direct child's exit wins the session select and proceeds to finalization even if descendants are still alive.

```rust
        status = child.wait_for_natural_exit() => {
            match status {
                Ok(s) => {
                    let code = observed_exit_code(&s);
                    if let Some(label) = labels.child_exited {
                        tracing::info!("{label} with code {code}");
                    }
                    audit_logger.shutdown().await;
                    drop(child);
```

**Drop can signal the group only while a PID remains** — `src/warden/child.rs:250-264`

Tokio 1.53.1 returns no ID after a child has been polled to completion, so the natural-exit path skips the negative-PID group signal.

```rust
impl Drop for RunningChild {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            kill_unix_process_group(pid);
        }
        match &mut self.inner {
            RunningChildInner::Tokio(child) => {
                let _ = child.start_kill();
            }
            #[cfg(target_os = "windows")]
            RunningChildInner::Windows(child) => {
                let _ = child.kill();
            }
        }
```

**Unix containment tracks only the original process group** — `src/warden/child.rs:268-287`

No cgroup, subreaper, or retained PGID owns the descendant tree; all cleanup depends on recovering the original leader PID.

```rust
pub(super) fn apply_unix_process_group(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd;
}

pub(super) fn apply_unix_process_group_tokio(cmd: &mut tokio::process::Command) {
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let _ = cmd;
}

#[cfg(unix)]
fn kill_unix_process_group(pid: u32) {
    let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
```

#### Reachability

The path is unconditional on macOS because the generated profile grants `process-fork`; on Linux it depends on the configured syscall allowlist.

- **Attacker:** malicious or compromised MCP workload

- **Entry point:** workload process creation before direct-child exit

- **Outcome:** persistent background activity outside the intended session lifetime

Preconditions:
- The workload can create a descendant.
- The direct child exits while that descendant remains alive.
- The descendant retains a useful filesystem or network grant.

Limitations:
- Surviving descendants remain inside inherited sandbox rules.

#### Severity

**Medium** — A malicious workload can retain ongoing access and side effects after `mcp-writ` reports the session complete. Descendants remain under inherited Landlock/seccomp or SBPL restrictions, so the issue extends grant lifetime rather than escaping those controls.

Severity increases for policies with sensitive writable paths or network grants and on macOS where `process-fork` is always granted; it decreases on Linux policies that deny every process-creation primitive.

Impact assessment:
- **Level:** medium
- **Why:** The descendant can continue authorized reads, writes, or network activity after the user believes containment ended.

Likelihood assessment:
- **Level:** medium
- **Why:** Malicious workloads can deliberately fork on macOS; Linux depends on syscall policy.

#### Remediation

Retain the original PGID independently of the direct child handle and kill it before finalizing any natural exit; use a cgroup or equivalent descendant-tree ownership primitive where available, and prevent or account for descendants that create a new session or process group.

Tests:
- Launch a workload that forks a sleeping child and exits the leader; assert that no descendant remains after `mcp-writ` finalizes.
- Repeat with the descendant remaining in the original group and, where permitted, moving to a new session.
- Verify explicit kill, natural exit, relay exit, and drop paths all perform descendant cleanup.

Preventive controls:
- Model process-tree lifetime as an owned enforcement resource rather than deriving it from a live leader handle.
- Report descendant containment separately from inherited filesystem and network sandboxing.

<a id="finding-6"></a>

### [6] A renamed interpreter can execute code outside required identity pins

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | The source separately resolves the executable but passes only original argv into every interpreter grammar check, and then spawns the resolved executable with the original argument vector. |
| Category | incomplete-workload-identity-binding |
| CWE | CWE-184 |
| Affected lines | src/workload.rs:40-73, src/workload.rs:159-180, src/verifier/hash.rs:281-295, src/runtime/launch.rs:194-218, src/runtime/launch.rs:296-315 |

#### Summary

The runtime resolves and hashes the canonical executable, but inline-evaluation, payload, and preload grammar are selected only from the caller's `argv[0]` spelling. A symlink or alias with an unrecognized name can resolve to a pinned interpreter while flags such as Python `-c`, Node `--eval`, or preload options evade the unbound-workload checks.

#### Root Cause

The violated invariant is that workload grammar must be derived from the executable that will interpret it. Executable resolution and hashing use `resolved_exe`, while inline, payload-boundary, and preload analysis classify only `argv[0]`. Renaming or symlinking a supported interpreter splits those views and lets unpinned code run under a verified binary identity.

**Interpreter family depends on caller spelling** — `src/workload.rs:40-50`

Classification considers only the untrusted launch spelling. A name such as `worker` remains unknown even when path resolution points to Python or Node.

```rust
/// Classify an interpreter by its `argv[0]` spelling (`python3`,
/// `C:\tools\node.exe`, `py`, `npx`, …). Versioned and `.exe`-suffixed
/// names resolve to their family.
pub fn interpreter_from_command(argv0: &str) -> Option<InterpreterKind> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
```

**Inline-evaluation checks reuse only original argv** — `src/workload.rs:159-180`

The security check never receives the already resolved executable path, so every family-specific inline flag becomes an ordinary argument under an alias.

```rust
pub(crate) fn argv_contains_inline_eval(argv: &[String]) -> bool {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let end = first_payload_arg_index(argv).unwrap_or(argv.len());
    if argv[..end].iter().any(|a| is_inline_eval_flag(a, argv0)) {
        return true;
    }
    // Windows PowerShell (`powershell.exe`, unlike `pwsh`) binds a
    // positional argument that is not a script path as an implicit
    // `-Command`: `powershell Get-Process` evaluates `Get-Process`.
    // `-File` makes its operand a file regardless of extension, and a
    // `.ps1` payload is always a script.
    if command_stem(argv0) != "powershell" {
        return false;
    }
    let Some(idx) = first_payload_arg_index(argv) else {
        return false;
    };
    !argv[..idx]
        .iter()
        .any(|a| powershell_flag_is_named(a, "file"))
        && !argv[idx].to_ascii_lowercase().ends_with(".ps1")
}
```

**Identity binding accepts the missed inline payload** — `src/verifier/hash.rs:281-295`

When alias-based parsing returns false, the binder proceeds to hash only the interpreter image and can mark the launch bound without hashing the inline code.

```rust
    if argv_contains_inline_eval(argv) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "inline evaluation flags (-c/-e/--eval/--command incl. attached \
                 and = spellings, -p/--print on node, -E on perl) are not a \
                 hash-bindable workload"
                .into(),
        });
    }

    let exe_hash = hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
```

**The pinned interpreter executes the unchecked arguments** — `src/runtime/launch.rs:296-315`

The security decision and actual launch intentionally combine a canonical executable with the caller's original argv, so the interpreter consumes the flags the alias hid from validation.

```rust
    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    let attempt = match sandbox_skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &resolved_exe,
            &argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden
                .spawn_child_async_exe_with_report(&resolved_exe, &argv, &spawn_opts, dry_run)
```

#### Validation

A nonstandard alias resolves to a pinned interpreter but remains an unknown family to every argument check.

Validation method: static source trace

**Interpreter family depends on caller spelling** — `src/workload.rs:40-50`

Classification considers only the untrusted launch spelling. A name such as `worker` remains unknown even when path resolution points to Python or Node.

```rust
/// Classify an interpreter by its `argv[0]` spelling (`python3`,
/// `C:\tools\node.exe`, `py`, `npx`, …). Versioned and `.exe`-suffixed
/// names resolve to their family.
pub fn interpreter_from_command(argv0: &str) -> Option<InterpreterKind> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
```

**Inline-evaluation checks reuse only original argv** — `src/workload.rs:159-180`

The security check never receives the already resolved executable path, so every family-specific inline flag becomes an ordinary argument under an alias.

```rust
pub(crate) fn argv_contains_inline_eval(argv: &[String]) -> bool {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let end = first_payload_arg_index(argv).unwrap_or(argv.len());
    if argv[..end].iter().any(|a| is_inline_eval_flag(a, argv0)) {
        return true;
    }
    // Windows PowerShell (`powershell.exe`, unlike `pwsh`) binds a
    // positional argument that is not a script path as an implicit
    // `-Command`: `powershell Get-Process` evaluates `Get-Process`.
    // `-File` makes its operand a file regardless of extension, and a
    // `.ps1` payload is always a script.
    if command_stem(argv0) != "powershell" {
        return false;
    }
    let Some(idx) = first_payload_arg_index(argv) else {
        return false;
    };
    !argv[..idx]
        .iter()
        .any(|a| powershell_flag_is_named(a, "file"))
        && !argv[idx].to_ascii_lowercase().ends_with(".ps1")
}
```

**Identity binding accepts the missed inline payload** — `src/verifier/hash.rs:281-295`

When alias-based parsing returns false, the binder proceeds to hash only the interpreter image and can mark the launch bound without hashing the inline code.

```rust
    if argv_contains_inline_eval(argv) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "inline evaluation flags (-c/-e/--eval/--command incl. attached \
                 and = spellings, -p/--print on node, -E on perl) are not a \
                 hash-bindable workload"
                .into(),
        });
    }

    let exe_hash = hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
```

**The pinned interpreter executes the unchecked arguments** — `src/runtime/launch.rs:296-315`

The security decision and actual launch intentionally combine a canonical executable with the caller's original argv, so the interpreter consumes the flags the alias hid from validation.

```rust
    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    let attempt = match sandbox_skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &resolved_exe,
            &argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden
                .spawn_child_async_exe_with_report(&resolved_exe, &argv, &spawn_opts, dry_run)
```

Assertions:
- The resolved executable path is available before binding but is not passed to interpreter-family detection.
- Unknown-family `-c`, `--eval`, or preload spellings do not trigger the fail-closed inline check.
- The verified resolved interpreter executes the original arguments.

Counterevidence and remaining uncertainty:
- Conventional interpreter names and versioned aliases are recognized.
- A separately required entrypoint hash can bind a file payload.
- The OS sandbox still constrains the executed code.

Limitations:
- No alias-based runtime reproduction was executed.

#### Dataflow

alias argv0 -\> canonical interpreter resolution -\> unknown-family argument scan -\> interpreter binary hash passes -\> resolved interpreter executes unchecked code

Attack steps:
- Provide a nonstandard symlink or alias to a pinned interpreter.
- Launch it with the interpreter's inline or preload option.
- The family check treats the alias as a native binary and hashes only the resolved interpreter.
- The verified interpreter executes the unpinned code.

- **Source:** attacker-influenced alias name and interpreter arguments

- **Sink:** resolved interpreter process

- **Outcome:** code outside the required binary or entrypoint pins executes

**Interpreter family depends on caller spelling** — `src/workload.rs:40-50`

Classification considers only the untrusted launch spelling. A name such as `worker` remains unknown even when path resolution points to Python or Node.

```rust
/// Classify an interpreter by its `argv[0]` spelling (`python3`,
/// `C:\tools\node.exe`, `py`, `npx`, …). Versioned and `.exe`-suffixed
/// names resolve to their family.
pub fn interpreter_from_command(argv0: &str) -> Option<InterpreterKind> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
```

**Inline-evaluation checks reuse only original argv** — `src/workload.rs:159-180`

The security check never receives the already resolved executable path, so every family-specific inline flag becomes an ordinary argument under an alias.

```rust
pub(crate) fn argv_contains_inline_eval(argv: &[String]) -> bool {
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let end = first_payload_arg_index(argv).unwrap_or(argv.len());
    if argv[..end].iter().any(|a| is_inline_eval_flag(a, argv0)) {
        return true;
    }
    // Windows PowerShell (`powershell.exe`, unlike `pwsh`) binds a
    // positional argument that is not a script path as an implicit
    // `-Command`: `powershell Get-Process` evaluates `Get-Process`.
    // `-File` makes its operand a file regardless of extension, and a
    // `.ps1` payload is always a script.
    if command_stem(argv0) != "powershell" {
        return false;
    }
    let Some(idx) = first_payload_arg_index(argv) else {
        return false;
    };
    !argv[..idx]
        .iter()
        .any(|a| powershell_flag_is_named(a, "file"))
        && !argv[idx].to_ascii_lowercase().ends_with(".ps1")
}
```

**Identity binding accepts the missed inline payload** — `src/verifier/hash.rs:281-295`

When alias-based parsing returns false, the binder proceeds to hash only the interpreter image and can mark the launch bound without hashing the inline code.

```rust
    if argv_contains_inline_eval(argv) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "inline evaluation flags (-c/-e/--eval/--command incl. attached \
                 and = spellings, -p/--print on node, -E on perl) are not a \
                 hash-bindable workload"
                .into(),
        });
    }

    let exe_hash = hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
```

**The pinned interpreter executes the unchecked arguments** — `src/runtime/launch.rs:296-315`

The security decision and actual launch intentionally combine a canonical executable with the caller's original argv, so the interpreter consumes the flags the alias hid from validation.

```rust
    // The child execs `resolved_exe` — the canonicalized, hash-verified
    // image — while `argv` keeps the caller's spelling as the child's
    // argv[0]: a venv `bin/python` locates `pyvenv.cfg` relative to it
    // (on macOS, where CPython ignores argv[0], the Warden passes the
    // spelling via PYTHONEXECUTABLE). Passing the symlink itself to
    // spawn would exec the unverified link.
    if let Some(reason) = sandbox_skip_reason {
        tracing::warn!("sandboxing disabled ({reason})");
    }
    let attempt = match sandbox_skip_reason {
        Some(reason) => warden.spawn_unsandboxed_async_exe_with_report(
            &resolved_exe,
            &argv,
            &spawn_opts,
            reason,
            dry_run,
        ),
        None => {
            warden
                .spawn_child_async_exe_with_report(&resolved_exe, &argv, &spawn_opts, dry_run)
```

#### Reachability

The attacker must influence the workload command or package-provided alias while the policy requires identity hashes but does not separately bind the inline/preloaded code.

- **Attacker:** malicious MCP package or launch configuration contributor

- **Entry point:** server command argv under a hash-enforcing policy

- **Outcome:** unpinned code runs with the workload's sandbox grants

Preconditions:
- The alias resolves to a supported pinned interpreter.
- The caller supplies inline-evaluation, module, or preload arguments.
- No independent entrypoint pin covers the executed code.

Limitations:
- No concrete MCP package configuration was reproduced.

#### Severity

**Medium** — The bypass defeats an explicitly required supply-chain identity control and allows attacker-controlled inline or preloaded code to execute under a verified interpreter record. The code remains within the configured OS sandbox, limiting the impact to the workload's granted authority.

Severity increases when the workload receives sensitive filesystem, network, or environment grants and decreases when an entrypoint pin or launcher configuration independently fixes the executed payload.

Impact assessment:
- **Level:** medium
- **Why:** The attack defeats supply-chain workload identity but does not itself escape OS sandbox controls.

Likelihood assessment:
- **Level:** medium
- **Why:** Package-local aliases and interpreter-based MCP servers are common, but exploitation requires influence over the launch command.

#### Remediation

Classify workload grammar from both original `argv[0]` and `resolved_exe`; if either identifies a supported interpreter, apply the stricter family parser and reject inline, module, preload, or ambiguous payload forms not covered by an identity pin.

Tests:
- Create aliases to Python, Node, shells, Perl, Ruby, PowerShell, and cmd and assert that each family's inline-evaluation flags are rejected.
- Assert that Node preload flags through an alias cannot pass with only a binary hash.
- Preserve recognized virtual-environment launch behavior while deriving security grammar from the resolved image.

Preventive controls:
- Carry a typed resolved workload family from path resolution into every identity and payload check.
- Treat disagreement between caller spelling and resolved executable family as requiring the stricter parser.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| JSON-RPC correlation, tools/list verification, and argument policy | Untrusted MCP frames crossing the Auditor | Reported | Focused review validated numeric-ID aliasing and noncanonical-host SSRF candidates. |
| Independent repository-wide baseline review | Cross-cutting parser, path, resource, and command surfaces | Reported | The independent baseline produced two validated findings and two candidates rejected after source and attacker-boundary validation. |
| JSON-RPC request-ID memory accounting | Attacker-controlled protocol state and availability | Rejected | Rejected candidate cand-wire-id-memory. Original evidence: frames permit 1,048,576 bytes; `WireState` can retain 128 live and 128 retired owned `RpcId` values without a byte budget, so the source-backed upper bound is roughly 256 MiB plus overhead. Counterevidence: reaching that bound requires a local stdio peer to transfer hundreds of megabytes and maintain/cancel many requests; a malicious child server already runs without a repository-owned memory quota and can consume memory or terminate the session directly, while a normal MCP client—not prompt-controlled tool arguments—chooses request IDs. The path does not establish a meaningful new security capability across the modeled boundary. |
| Static artifact analysis file loading | Memory exhaustion while inspecting local binaries or source files | Rejected | Rejected candidate cand-artifact-memory. Original evidence: `inspect` and `generate-policy` call `std::fs::read`, and source analysis calls `fs::read_to_string`, without an application byte cap before allocation. Counterevidence: these paths analyze a file explicitly selected by the local operator or automation and are not reachable from proxied MCP traffic; the candidate established CLI robustness risk but no lower-trust input boundary or added attacker capability in the modeled deployment. |
| Native sandbox launch, workload identity, environment, and teardown | Security-helper selection, identity binding, ambient credentials, and descendant containment | Reported | Validated the macOS helper PATH, interpreter-alias, and Unix descendant-lifetime findings; documented environment and hash-race candidates were rejected. |
| Default child environment inheritance | Ambient credential exposure to launched workloads | Rejected | Rejected candidate cand-default-env-inheritance. Original evidence: `EnvironmentPolicy` defaults to `restrict=false`, `spawn_env_pairs()` returns `None` when no temporary override is needed, and the child then inherits the full parent environment. Counterevidence: this is an explicit launch contract documented in README.md, both policy-authoring guides, the field reference, example policy, source comments, and tests; declaring even an empty `defaults.environment {}` switches to deny-by-default inheritance. No silent policy bypass or mismatch between the documented and effective configuration was established. |
| Final workload hash-to-exec window | Pinned executable and payload identity at spawn | Rejected | Rejected candidate cand-hash-exec-race. Original evidence: `hash_file()` opens, hashes, and closes each path; the immediate reverify and later spawn do not share an immutable file handle, leaving a final pathname race. Counterevidence: source and user documentation explicitly state that reverification narrows but does not close this window, reports do not claim immutability, and exploitation requires local write/rename authority over the operator-pinned executable or payload path plus precise timing. Under the modeled attacker boundary this is a documented residual limitation, not a newly established remote or workload-controlled bypass. |
| Policy inheritance, target validation, server binding, and hash verification | Effective policy and workload identity | Reported | Reviewed policy loading, extends/when materialization, exact server binding, initial and pre-spawn hashes, environment contract, and code-identity reporting. The interpreter-alias finding is reported; the documented residual hash-to-exec window is retained as rejected coverage. |
| Linux, Windows, and macOS native enforcement | Filesystem, network, syscall, process, and descendant containment | Reported | Linux fail-closed setup and Windows AppContainer/Job paths showed no additional reportable fail-open path. macOS helper selection and Unix descendant lifetime are reported. |
| Container image validation, mounts, backend isolation, and guest reports | Host-to-engine and host-to-guest trust boundaries | No issue found | Reviewed digest pinning, remote-daemon checks, typed engine arguments, policy/log/report mounts, guest-side policy validation, report bounds and correlation, and cleanup. Guest enforcement remains explicitly self-reported; no authoritative-evidence bypass was found. |
| Audit logging and launch-report integrity | Fail-closed audit availability and enforcement observations | No issue found | Reviewed committed audit-before-forward behavior, bounded channels, failure propagation, launch-report lifecycle, and platform evidence wording. No source-backed secret value disclosure or false verified enforcement state was found. |
| Container build contexts and release workflow | Build inputs, workflow authority, and published artifacts | No issue found | Reviewed no-shell engine invocation, source-copy exclusions and symlink handling, job-scoped contents:write, pinned actions, packaging, and checksums. Manual-only release prerequisites remain documented operational controls. |

## Open Questions And Follow Up

- Pending parent validation of process-group teardown and detached descendants.
  - Follow-up prompt: Review deferred unit cand-unix-descendant-escape and close its stated proof gap. Paths: src/warden/child.rs, src/runtime/wait.rs, src/warden/macos_sandbox.rs. Surfaces: surface-sandbox-launch.
- Pending parent validation of the documented final hash-to-exec race and attacker prerequisites.
  - Follow-up prompt: Review deferred unit cand-hash-exec-race and close its stated proof gap. Paths: src/verifier/hash.rs, src/runtime/launch.rs. Surfaces: surface-sandbox-launch.
- Pending parent validation of default ambient environment inheritance as a security boundary.
  - Follow-up prompt: Review deferred unit cand-default-env-inheritance and close its stated proof gap. Paths: src/policy/mod.rs, src/runtime/launch.rs, src/warden/env.rs. Surfaces: surface-sandbox-launch.
- Pending parent validation of interpreter alias classification versus resolved executable identity.
  - Follow-up prompt: Review deferred unit cand-interpreter-alias and close its stated proof gap. Paths: src/workload.rs, src/verifier/hash.rs, src/runtime/launch.rs. Surfaces: surface-sandbox-launch.
- Pending parent validation of PATH-based `sandbox-exec` resolution and normal-mode sandbox bypass.
  - Follow-up prompt: Review deferred unit cand-macos-sandbox-path and close its stated proof gap. Paths: src/warden/mod.rs, src/warden/env.rs, src/warden/macos_sandbox.rs. Surfaces: surface-sandbox-launch.
- Pending parent validation of whole-file analysis reads and whether the input boundary is security-relevant.
  - Follow-up prompt: Review deferred unit cand-artifact-memory and close its stated proof gap. Paths: src/commands/inspect.rs, src/commands/generate_policy.rs, src/legislator/source_bind.rs. Surfaces: surface-independent-baseline.
- Pending parent validation of aggregate request-ID memory impact and attacker boundary.
  - Follow-up prompt: Review deferred unit cand-wire-id-memory and close its stated proof gap. Paths: src/framing.rs, src/auditor/session.rs, src/auditor/proxy_rpc.rs, src/auditor/proxy_c2s.rs. Surfaces: surface-independent-baseline.
- Pending parent validation of non-local file URL authority handling and Windows downstream semantics.
  - Follow-up prompt: Review deferred unit cand-file-url-authority and close its stated proof gap. Paths: src/pathutil.rs, src/auditor/checker.rs. Surfaces: surface-independent-baseline.
- Pending parent validation of URL host canonicalization and downstream parser differential.
  - Follow-up prompt: Review deferred unit cand-ip-spelling-alias and close its stated proof gap. Paths: src/policy/mod.rs, src/policy/host.rs, src/auditor/checker.rs. Surfaces: surface-rpc-policy-boundary, surface-independent-baseline.
- Awaiting parent source validation.
  - Follow-up prompt: Review deferred unit cand-rpc-id-alias and close its stated proof gap.
