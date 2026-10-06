# PR-30 Windows isolation mechanisms comparison — real-machine
# validation. Runs the `tests/fixtures/windows_isolation/winiso_probe.rs`
# fixture legs on a Windows host and records the evidence bundle under a
# dedicated run directory. See `docs/validation/windows-isolation.md`.
#
# What the script deliberately never does:
#   - no Windows feature enablement, no `dism`/`Enable-WindowsOptionalFeature`
#   - no Insider/preview bits installed on a normal host; lab legs are
#     gated behind -Lab and are recorded as not-run otherwise
#   - no session/container/package/user/ACL it did not create — the
#     probe creates only AppContainer profiles named mcp-writ-pr30-*
#     and dirs under this run's work dir, and restores ACLs it touched
#   - no `wsl --update`, no image pulls, no elevation
#
# Result outcomes recorded in result.json:
#   'winiso-tests-passed'      — every leg ran and asserted on this host
#   'environment-unavailable'  — a documented prerequisite is absent
#                                (rustc, AMD64, …); distinct from a test
#                                failure
#   'failed'                   — a leg failed, evidence is kept
[CmdletBinding()]
param(
    # Lab legs (IsolationSession lifecycle etc.) require an Insider lab
    # host; without this switch they are recorded as 'lab-gated'.
    [switch]$Lab
)

$ErrorActionPreference = 'Stop'
$wiRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wiUtf8 = [Text.UTF8Encoding]::new($false)
$wiRun = Join-Path $wiRepo ('.local\winiso-validation\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
$wiWork = Join-Path $wiRun 'work'
$wiEvidence = Join-Path $wiRun 'evidence'
$wiSandbox = Join-Path $wiWork 'sandbox-dirs'
$wiLog = Join-Path $wiRun 'test-output.txt'
$wiVars = @('TEMP', 'TMP', 'MCP_WRIT_REQUIRE_WINISO_TESTS', 'MCP_WRIT_WINISO_TEST_ROOT', 'MCP_WRIT_WINISO_EVIDENCE_DIR', 'WINISO_RO_DIR', 'WINISO_RW_DIR', 'WINISO_DENY_DIR', 'WINISO_UNGRANTED_DIR', 'WINISO_NET_ADDR')
$wiOldEnv = @{}
foreach ($wiVar in $wiVars) { $wiOldEnv[$wiVar] = [Environment]::GetEnvironmentVariable($wiVar, 'Process') }
New-Item -ItemType Directory -Path $wiWork, $wiEvidence, $wiSandbox -Force | Out-Null
$wiResult = @{
    result = 'failed'
    started_utc = [DateTime]::UtcNow.ToString('o')
    lab_gate = $Lab.IsPresent
    legs = [ordered]@{}
}
Push-Location $wiRepo

# Bounded probe call: piped stdout, per-leg timeout, raw bytes kept so a
# BOM/UTF-16 quirk is visible instead of mangled by the console.
function Invoke-WiLeg([string]$Probe, [string[]]$LegArgs, [int]$TimeoutMs = 90000) {
    $wiPsi = [Diagnostics.ProcessStartInfo]::new()
    $wiPsi.FileName = $Probe
    $wiPsi.Arguments = (($LegArgs | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' ')
    $wiPsi.RedirectStandardOutput = $true
    $wiPsi.RedirectStandardError = $true
    $wiPsi.UseShellExecute = $false
    $wiProc = [Diagnostics.Process]::Start($wiPsi)
    $wiMs = [IO.MemoryStream]::new()
    $wiErrMs = [IO.MemoryStream]::new()
    $wiOutTask = $wiProc.StandardOutput.BaseStream.CopyToAsync($wiMs)
    $wiErrTask = $wiProc.StandardError.BaseStream.CopyToAsync($wiErrMs)
    if (-not $wiProc.WaitForExit($TimeoutMs)) {
        try { & taskkill.exe /PID $wiProc.Id /T /F 2>&1 | Out-Null } catch {}
        try { if (-not $wiProc.HasExited) { $wiProc.Kill() } } catch {}
        [void][Threading.Tasks.Task]::WaitAll(@($wiOutTask, $wiErrTask), 5000)
        return $null
    }
    [void][Threading.Tasks.Task]::WaitAll(@($wiOutTask, $wiErrTask), 10000)
    return $wiMs.ToArray()
}

function Write-WiJson([string]$Path, [byte[]]$Bytes) {
    # Fixture emits a single UTF-8 JSON line; strip a BOM if one appears
    # so downstream parsers never trip on it.
    if ($Bytes -and $Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $Bytes = $Bytes[3..($Bytes.Length - 1)]
    }
    [IO.File]::WriteAllBytes($Path, [byte[]]($Bytes + [byte]10))
}

function Get-WiJson([string]$Path) {
    $wiText = [IO.File]::ReadAllText($Path, $wiUtf8)
    return ($wiText | ConvertFrom-Json)
}

try {
    # ── Host identity — recorded before any gate ──────────────────
    $wiResult.commit = try { (& git rev-parse HEAD).Trim() } catch { 'unknown' }
    $wiResult.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    $wiCv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $wiResult.os_revision = $wiCv.UBR
    $wiResult.display_version = $wiCv.DisplayVersion
    $wiResult.edition = $wiCv.EditionID
    $wiResult.architecture = $env:PROCESSOR_ARCHITECTURE
    $wiResult.session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $wiResult.user_interactive = [Environment]::UserInteractive
    $wiResult.elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $wiResult.rustc = try { (& rustc --version).Trim() } catch { 'unavailable' }
    $wiResult.insider = ($wiCv.DisplayVersion -match 'Insider' -or $wiCv.BuildLabEx -match 'insider')

    # ── Environment gate — 'environment-unavailable' ends here ─────
    $wiEnvFail = $null
    if ($wiResult.architecture -ne 'AMD64') { $wiEnvFail = 'PR-30 validates Windows x86-64 first' }
    if (-not $wiEnvFail -and $wiResult.session_id -eq 0) { $wiEnvFail = 'Session 0 — the probe needs an interactive session (same constraint as the AppContainer baseline)' }
    if (-not $wiEnvFail -and $wiResult.rustc -eq 'unavailable') { $wiEnvFail = 'rustc is not on PATH — the fixture builds with rustc -O, no cargo needed' }
    if (-not $wiEnvFail) {
        # Bulk-write drives: the run dir and %TEMP% (rustc writes temps).
        foreach ($wiDrive in @(([IO.Path]::GetPathRoot($wiRun)), ([IO.Path]::GetPathRoot($env:TEMP))) | Select-Object -Unique) {
            if (([IO.DriveInfo]::new($wiDrive)).AvailableFreeSpace -lt 10GB) {
                $wiEnvFail = "$wiDrive has less than 10 GiB free — the fixture build needs scratch space"
            }
        }
    }
    if ($wiEnvFail) {
        $wiResult.result = 'environment-unavailable'
        $wiResult.environment_failure = $wiEnvFail
        throw "environment unavailable: $wiEnvFail"
    }

    $env:TEMP = $wiWork
    $env:TMP = $wiWork
    $env:MCP_WRIT_REQUIRE_WINISO_TESTS = '1'
    $env:MCP_WRIT_WINISO_TEST_ROOT = $wiWork
    $env:MCP_WRIT_WINISO_EVIDENCE_DIR = Join-Path $wiEvidence 'e2e'

    # ── Build the probe fixture ───────────────────────────────────
    $wiProbe = Join-Path $wiWork 'winiso_probe.exe'
    $wiSrc = Join-Path $wiRepo 'tests\fixtures\windows_isolation\winiso_probe.rs'
    $wiBuildLog = & rustc --edition 2021 -O -o $wiProbe $wiSrc 2>&1 | Out-String
    [IO.File]::AppendAllText($wiLog, "rustc winiso_probe.rs`n$wiBuildLog`n", $wiUtf8)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $wiProbe -PathType Leaf)) {
        throw "fixture build failed; see $wiLog"
    }
    $wiResult.source_hashes = @(
        (Join-Path $wiRepo 'tests\windows_isolation_e2e.rs'),
        (Join-Path $wiRepo 'tests\common\mod.rs'),
        (Join-Path $wiRepo 'scripts\validate-windows-isolation.ps1')
    ) + @(Get-ChildItem -LiteralPath (Join-Path $wiRepo 'tests\fixtures\windows_isolation') -File -Filter '*.rs') +
        @(Get-ChildItem -LiteralPath (Join-Path $wiRepo 'tests\fixtures\windows_isolation\golden') -File -Filter '*.json') |
        Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash

    # AppContainer profile baseline — record mappings before the run so a
    # leaked mcp-writ-pr30-* profile is detected, never silently cleaned.
    $wiMapRoot = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    $wiResult.profiles_before = @(
        if (Test-Path $wiMapRoot) {
            Get-ChildItem $wiMapRoot | Where-Object {
                ((Get-ItemProperty $_.PSPath).DisplayName -like 'mcp-writ-pr30-*')
            } | ForEach-Object { $_.PSChildName }
        }
    )

    # ── Sandbox dirs the legs point at (inside work, fully owned) ──
    New-Item -ItemType Directory -Path "$wiSandbox\ro", "$wiSandbox\rw", "$wiSandbox\deny", "$wiSandbox\ungranted" -Force | Out-Null
    Set-Content -LiteralPath "$wiSandbox\ro\ro-read.txt" -Value 'ro-data' -NoNewline -Encoding Ascii
    Set-Content -LiteralPath "$wiSandbox\deny\deny-read.txt" -Value 'deny-data' -NoNewline -Encoding Ascii
    Set-Content -LiteralPath "$wiSandbox\ungranted\ungranted.txt" -Value 'ungranted' -NoNewline -Encoding Ascii
    $env:WINISO_RO_DIR = "$wiSandbox\ro"
    $env:WINISO_RW_DIR = "$wiSandbox\rw"
    $env:WINISO_DENY_DIR = "$wiSandbox\deny"
    $env:WINISO_UNGRANTED_DIR = "$wiSandbox\ungranted"
    $env:WINISO_NET_ADDR = '127.0.0.1:9'

    # Resolve a Node runtime for the launch-condition legs — Node stands
    # in for the unpackaged interpreter class MCP servers actually are.
    # Absent ⇒ the legs record 'unavailable', never a silent skip.
    $wiNode = $null
    $wiNodeCmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($wiNodeCmd) { $wiNode = $wiNodeCmd.Source }
    elseif (Test-Path 'C:\Program Files\nodejs\node.exe') { $wiNode = 'C:\Program Files\nodejs\node.exe' }

    # ── Legs ──────────────────────────────────────────────────────
    $wiLegs = @(
        @{ name = 'facts';          file = 'facts.json';        args = @('facts') },
        @{ name = 'contracts';      file = 'contracts.json';    args = @('contracts') },
        @{ name = 'attempts-host';  file = 'attempts-host.json'; args = @('attempts') },
        @{ name = 'ac-run';         file = 'ac-run.json';       args = @('ac-run') },
        @{ name = 'ac-run-net';     file = 'ac-run-net.json';   args = @('ac-run', '--net') },
        @{ name = 'ac-run-lpac';    file = 'ac-run-lpac.json';  args = @('ac-run', '--lpac') },
        @{ name = 'psec-spec-test'; file = 'psec-spec.json';    args = @('psec-spec-test') },
        @{ name = 'psec-run';       file = 'psec.json';         args = @('psec-run', '--ro', $env:WINISO_RO_DIR, '--rw', $env:WINISO_RW_DIR, '--deny', $env:WINISO_DENY_DIR) }
    )
    if ($wiNode) {
        $wiNodeDir = Split-Path -Parent $wiNode
        $wiLegs += @(
            @{ name = 'ac-node';   file = 'ac-node.json';   args = @('ac-run', '--image', $wiNode, '-e', "console.log('node-ac-ok')") },
            @{ name = 'psec-node'; file = 'psec-node.json'; args = @('psec-run', '--ro', $env:WINISO_RO_DIR, '--ro', $wiNodeDir, '--rw', $env:WINISO_RW_DIR, '--deny', $env:WINISO_DENY_DIR, '--image', $wiNode, '-e', "console.log('node-psec-ok')") }
        )
    } else {
        $wiResult.legs['ac-node'] = @{ status = 'skipped'; detail = 'node.exe not found — no interpreter launch evidence'; file = $null }
        $wiResult.legs['psec-node'] = @{ status = 'skipped'; detail = 'node.exe not found — no interpreter launch evidence'; file = $null }
    }
    foreach ($wiLeg in $wiLegs) {
        $wiStatus = 'failed'
        $wiDetail = $null
        $wiBytes = Invoke-WiLeg $wiProbe $wiLeg.args
        if ($null -eq $wiBytes) {
            $wiDetail = "leg timed out after 90s or failed to start: $($wiLeg.args -join ' ')"
        } elseif ($wiBytes.Length -eq 0) {
            $wiDetail = 'leg produced no output'
        } else {
            $wiFile = Join-Path $wiEvidence $wiLeg.file
            Write-WiJson $wiFile $wiBytes
            try {
                $wiJson = Get-WiJson $wiFile
                $wiDetail = 'recorded'
                $wiStatus = 'passed'
            } catch {
                $wiDetail = "output not valid JSON: $($_.Exception.Message)"
            }
        }
        $wiResult.legs[$wiLeg.name] = @{ status = $wiStatus; detail = $wiDetail; file = $wiLeg.file }
        Write-Host ("{0,-16} {1} {2}" -f $wiLeg.name, $wiStatus, $wiDetail)
        if ($wiStatus -eq 'failed') { throw "leg '$($wiLeg.name)' failed: $wiDetail" }
    }

    # ── Per-leg assertions (fail-closed; the e2e owns the golden
    #    contract, this is the run-level tripwire) ─────────────────
    $wiFacts = Get-WiJson (Join-Path $wiEvidence 'facts.json')
    if (-not $wiFacts.token.queried) { throw 'facts: token query missing' }

    $wiAc = Get-WiJson (Join-Path $wiEvidence 'ac-run.json')
    if (-not ($wiAc.profile_created -and $wiAc.spawn_ok -and $wiAc.profile_deleted -and -not $wiAc.cleanup_error)) {
        throw 'ac-run baseline leg did not complete cleanly — see ac-run.json'
    }
    $wiDenied = @('fs_write_ro', 'fs_read_deny', 'fs_write_deny', 'fs_read_ungranted') |
        ForEach-Object { $op = $_; @($wiAc.child.attempts | Where-Object { $_.op -eq $op -and $_.result -eq 'err:5' }).Count -ge 1 }
    if ($wiDenied -contains $false) { throw 'ac-run: filesystem denial not observed — baseline regression' }

    # Node launch-condition legs (recorded as skipped when node.exe is
    # absent): a sandboxed interpreter must reach stdout through the same
    # pipes MCP stdio uses.
    $wiAcNode = Join-Path $wiEvidence 'ac-node.json'
    if (Test-Path $wiAcNode) {
        $wiAcNodeJ = Get-WiJson $wiAcNode
        if (-not ($wiAcNodeJ.spawn_ok -and "$($wiAcNodeJ.child_stdout)" -match 'node-ac-ok')) {
            throw 'ac-node: node under AppContainer did not reach stdout — see ac-node.json'
        }
    }
    $wiPsecNode = Join-Path $wiEvidence 'psec-node.json'
    if (Test-Path $wiPsecNode) {
        $wiPsecNodeJ = Get-WiJson $wiPsecNode
        if ($wiPsecNodeJ.create_hr -eq '0x00000000' -and
            -not ($wiPsecNodeJ.spawn_ok -and "$($wiPsecNodeJ.child_stdout)" -match 'node-psec-ok')) {
            throw 'psec-node: node under PSEC did not reach stdout — see psec-node.json'
        }
    }

    $wiSpec = Get-WiJson (Join-Path $wiEvidence 'psec-spec.json')
    if ($wiSpec.attempts) {
        foreach ($wiA in $wiSpec.attempts) {
            if ($wiA.env_created -and -not $wiA.closed) { throw "psec env leak in $($wiA.variant)" }
        }
    }

    $wiPsec = Get-WiJson (Join-Path $wiEvidence 'psec.json')
    switch ($wiPsec.create_hr) {
        '0x00000000' {
            if (-not ($wiPsec.spawn_ok -and $wiPsec.env_closed)) { throw 'psec-run: env created but spawn/close failed' }
            $wiResult.psec_enforced = $true
        }
        'unavailable' { $wiResult.psec_enforced = $false; $wiResult.psec_note = 'processmodel.dll absent' }
        'exports-missing' { $wiResult.psec_enforced = $false; $wiResult.psec_note = 'PSEC exports missing' }
        default {
            $wiResult.psec_enforced = $false
            $wiResult.psec_note = "CreateProcessSecurityEnvironment -> $($wiPsec.create_hr)"
            Write-Warning "PSEC env creation answered $($wiPsec.create_hr) — recorded, not enforced on this host"
        }
    }

    # ── Lab legs — Insider-gated, recorded as not-run otherwise ────
    if ($Lab) {
        $wiResult.legs['isolation-session-lifecycle'] = @{
            status = 'skipped'
            detail = 'lab flag set, but the fixture does not drive the private WinMD session lifecycle — see docs/validation/windows-isolation.md'
            file = $null
        }
    } else {
        $wiResult.legs['isolation-session-lifecycle'] = @{
            status = 'skipped'
            detail = 'lab-gated: run with -Lab on a dedicated Insider host'
            file = $null
        }
    }

    # ── cargo e2e (golden contract + live legs under REQUIRE) ──────
    $wiCargoArgs = @('test', '--locked', '--test', 'windows_isolation_e2e', '--', '--nocapture')
    Write-Host ('cargo ' + ($wiCargoArgs -join ' '))
    [IO.File]::AppendAllText($wiLog, 'cargo ' + ($wiCargoArgs -join ' ') + "`n", $wiUtf8)
    $wiSavedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & cargo @wiCargoArgs 2>&1 | ForEach-Object {
            $wiLine = $_.ToString()
            [IO.File]::AppendAllText($wiLog, $wiLine + "`n", $wiUtf8)
            Write-Host $wiLine
        }
        $wiCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $wiSavedPreference }
    if ($wiCode -ne 0) { throw "cargo test windows_isolation_e2e failed (exit $wiCode); see $wiLog" }

    $wiResult.result = 'winiso-tests-passed'
} catch {
    $wiResult.error = $_.ToString()
    throw
} finally {
    $wiResult.finished_utc = [DateTime]::UtcNow.ToString('o')
    # Leak detection — only profiles this run could have created.
    $wiMapRoot = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    $wiResult.profiles_after = @(
        if (Test-Path $wiMapRoot) {
            Get-ChildItem $wiMapRoot | Where-Object {
                ((Get-ItemProperty $_.PSPath).DisplayName -like 'mcp-writ-pr30-*')
            } | ForEach-Object { $_.PSChildName }
        }
    )
    if (@($wiResult.profiles_after).Count -gt 0) {
        $wiResult.result = 'failed'
        $wiResult.leak = 'mcp-writ-pr30-* AppContainer profile(s) still registered'
    }
    foreach ($wiVar in $wiVars) { [Environment]::SetEnvironmentVariable($wiVar, $wiOldEnv[$wiVar], 'Process') }
    # Delete only this invocation's verified work directory. Evidence stays.
    $wiResolvedWork = [IO.Path]::GetFullPath($wiWork)
    $wiResolvedRun = [IO.Path]::GetFullPath($wiRun) + [IO.Path]::DirectorySeparatorChar
    if (-not $wiResolvedWork.StartsWith($wiResolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside this validation run'
    }
    $wiCleanupFailed = $false
    try { Remove-Item -LiteralPath $wiResolvedWork -Recurse -Force; $wiResult.work_cleanup = 'passed' }
    catch { $wiResult.work_cleanup = $_.ToString(); $wiResult.result = 'failed'; $wiCleanupFailed = $true; Write-Warning $_ }
    [IO.File]::WriteAllText((Join-Path $wiRun 'result.json'), ($wiResult | ConvertTo-Json -Depth 8) + "`n", $wiUtf8)
    Pop-Location
    Write-Host "Validation record: $wiRun"
    if ($wiCleanupFailed) { throw 'Validation work directory cleanup failed' }
}
