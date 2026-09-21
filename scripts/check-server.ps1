# check-server — run a real MCP server through mcp-writ and verify the
# handshake and (optionally) one tools/call survive the policy layers.
#
# Usage:
#   check-server --policy <kdl> [--audit-log <path>] [--call <json params>]
#                [--mcp-writ <path>] -- <server command...>
#
# On PowerShell the `--` separator is unnecessary: everything not matching a
# named parameter lands in -ServerCommand. A leading `--` is stripped if a
# caller (e.g. `&` invocation) passes it through literally.
#
# Stages:
#   1. dry-run (Auditor only): initialize + notifications/initialized + tools/list
#   2. sandboxed: the same exchange under the OS sandbox
#   3. sandboxed: one tools/call when --call is given
#
# Each expected response must contain "result" and must not contain "error";
# a call response must not have result.isError = true. Fails non-zero
# otherwise.
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$Policy,
    [string]$AuditLog,
    [string]$Call,
    [string]$McpWrit = 'mcp-writ',
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$ServerCommand
)

$ErrorActionPreference = 'Stop'

# Strip a literal `--` separator if one reached the remaining arguments.
if ($ServerCommand.Count -gt 0 -and $ServerCommand[0] -eq '--') {
    $ServerCommand = $ServerCommand[1..($ServerCommand.Count - 1)]
}

$INIT  = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check-server","version":"0"}}}'
$NOTIF = '{"jsonrpc":"2.0","method":"notifications/initialized"}'
$LIST  = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

if (-not (Get-Command $McpWrit -ErrorAction SilentlyContinue)) {
    Write-Error "check-server: FAIL — mcp-writ not found: $McpWrit"
    exit 1
}
if (-not $AuditLog) {
    $AuditLog = Join-Path $env:TEMP ("check-server-audit-" + [guid]::NewGuid().Guid + '.jsonl')
}

# Windows command-line quoting (CommandLineToArgvW rules): wrap in quotes,
# double backslashes before a quote or the end, backslash-escape quotes.
function Quote-Arg([string]$a) {
    $escaped = [regex]::Replace($a, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

# Send the request lines to the guard's stdin; return its stdout lines.
function Invoke-Stage([string[]]$Requests, [switch]$DryRun) {
    $runArgs = @('run', '--transport', 'stdio', '--policy', $Policy, '--audit-log', $AuditLog)
    if ($DryRun) { $runArgs += '--dry-run' }
    $runArgs += '--'
    $runArgs += $ServerCommand
    $stdin = ($Requests -join "`n") + "`n"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $McpWrit
    # ArgumentList is unavailable on Windows PowerShell 5.1 (netfx).
    $psi.Arguments = (($runArgs | ForEach-Object { Quote-Arg $_ }) -join ' ')
    Write-Verbose "argv: $($psi.Arguments)"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    # stderr is inherited so guard diagnostics reach the console.
    $psi.UseShellExecute = $false
    # .NET exceptions (a failed Process::Start, a stdin write to a dead
    # child) terminate regardless of $ErrorActionPreference — catch them so
    # one bad stage reports a failure instead of ending the script early.
    $p = $null
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        # Drain stdout asynchronously: a synchronous ReadToEnd blocks until
        # the child closes the pipe, so a wedged guard would never reach
        # the timed wait below (and a chatty child could fill the pipe
        # during the stdin hold).
        $stdoutRead = $p.StandardOutput.ReadToEndAsync()
        $p.StandardInput.Write($stdin)
        $p.StandardInput.Flush()
        # Hold stdin open briefly so in-flight responses are relayed before
        # the guard shuts down on EOF.
        Start-Sleep -Seconds 3
        $p.StandardInput.Close()
        # Finite wait: a guard that did not exit in time is killed so the
        # stage reports a failure instead of hanging the whole check, and
        # cleanup still reaches the finally block.
        if (-not $p.WaitForExit(60000)) {
            Write-Error "check-server: stage timed out after 60s; killing the guard process"
            try { $p.Kill() } catch {}
            return @()
        }
        $out = $stdoutRead.Result
        return $out -split "`r?`n"
    } catch {
        Write-Error "check-server: stage invocation failed: $($_.Exception.Message)"
        if ($null -ne $p) {
            try { if (-not $p.HasExited) { $p.Kill() } } catch {}
        }
        return @()
    } finally {
        if ($null -ne $p) { $p.Dispose() }
    }
}

# Structural judgment via ConvertFrom-Json: every JSON-RPC line must carry a
# result and no error; a call response must not have result.isError.
function Test-Responses([string]$Label, [string[]]$Lines, [switch]$IsCall) {
    $responses = @()
    foreach ($line in $Lines) {
        if ($line -notmatch '"jsonrpc"') { continue }
        try { $responses += ,($line | ConvertFrom-Json) } catch {}
    }
    foreach ($r in $responses) {
        # Host stream, not the output stream: Test-Responses must return
        # only its boolean verdict, or callers see a non-empty array.
        Write-Host ($r | ConvertTo-Json -Compress -Depth 20)
    }
    if ($responses.Count -lt 1) {
        Write-Error "check-server: FAIL — $Label : no JSON-RPC response"
        return $false
    }
    foreach ($r in $responses) {
        if ($null -ne $r.PSObject.Properties['error']) {
            Write-Error "check-server: FAIL — $Label : response carries `"error`""
            return $false
        }
        if ($null -eq $r.PSObject.Properties['result']) {
            Write-Error "check-server: FAIL — $Label : response missing `"result`""
            return $false
        }
        if ($IsCall -and $null -ne $r.result.PSObject.Properties['isError'] -and $r.result.isError) {
            Write-Error "check-server: FAIL — $Label : tools/call result isError"
            return $false
        }
    }
    return $true
}

$fail = $false

$requests = @($INIT, $NOTIF, $LIST)

Write-Output '== stage 1: dry-run =='
$ErrorActionPreference = 'Continue'
if (-not (Test-Responses 'stage 1 (dry-run)' (Invoke-Stage $requests -DryRun))) { $fail = $true }

Write-Output '== stage 2: sandboxed =='
if (-not (Test-Responses 'stage 2 (sandboxed)' (Invoke-Stage $requests))) { $fail = $true }

if ($Call) {
    $callLine = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":' + $Call + '}'
    Write-Output '== stage 3: tools/call (sandboxed) =='
    if (-not (Test-Responses 'stage 3 (tools/call)' (Invoke-Stage @($INIT, $NOTIF, $callLine)) -IsCall)) { $fail = $true }
}
$ErrorActionPreference = 'Stop'

Write-Output '== audit log (last 20 lines) =='
if (Test-Path $AuditLog) {
    Get-Content $AuditLog -Tail 20
} else {
    Write-Output '(no audit log written)'
}

if ($fail) {
    Write-Output 'check-server: FAIL'
    exit 1
}
Write-Output 'check-server: PASS'
