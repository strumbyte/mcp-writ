# PR-28 WSL Containers (`wslc`) validation. Run in a normal interactive
# PowerShell session on a Windows host where the `wslc` CLI is present
# (WSL product >= 2.9.3, the documented floor — see
# `docs/validation/wslc.md`). The script never runs `wsl --update`, never
# substitutes a `wsl.exe` distro or a Docker daemon, and never touches a
# WSLC session it did not name: the suite only creates `mcp-writ-wslc-*`
# units/images inside the default session and fully-owned
# `mcp-writ-wslc-sess-*` dedicated sessions under the run's own storage
# root.
#
# Result outcomes recorded in result.json:
#   'wslc-tests-passed'        — every leg ran and asserted on this host
#   'environment-unavailable'  — a documented prerequisite is absent
#                                (wslc CLI, WSL floor, musl toolchain, …);
#                                distinct from a test failure, and the
#                                correct record on a host that cannot
#                                run the substrate
#   'failed'                   — a test failed, evidence is kept
[CmdletBinding()]
param(
    [ValidateRange(1, 10)][int]$Repetitions = 1
)

$ErrorActionPreference = 'Stop'
$wslcRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wslcUtf8 = [Text.UTF8Encoding]::new($false)
$wslcRun = Join-Path $wslcRepo ('.local\wslc-validation\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
$wslcWork = Join-Path $wslcRun 'work'
$wslcEvidence = Join-Path $wslcRun 'evidence'
$wslcSessionRoot = Join-Path $wslcWork 'session-storage'
$wslcLog = Join-Path $wslcRun 'test-output.txt'
$wslcVars = @('TEMP', 'TMP', 'CARGO_INCREMENTAL', 'MCP_WRIT_REQUIRE_WSLC_TESTS', 'MCP_WRIT_WSLC_TEST_ROOT', 'MCP_WRIT_WSLC_EVIDENCE_DIR', 'MCP_WRIT_WSLC_SESSION_ROOT')
$wslcOldEnv = @{}
foreach ($wslcVar in $wslcVars) { $wslcOldEnv[$wslcVar] = [Environment]::GetEnvironmentVariable($wslcVar, 'Process') }
New-Item -ItemType Directory -Path $wslcWork, $wslcEvidence, $wslcSessionRoot -Force | Out-Null
$wslcResult = @{ repetitions = $Repetitions; result = 'failed'; started_utc = [DateTime]::UtcNow.ToString('o') }
Push-Location $wslcRepo

function Invoke-WslcCargo([string[]]$CargoArgs) {
    $wslcLine = 'cargo ' + ($CargoArgs -join ' ')
    Write-Host $wslcLine
    [IO.File]::AppendAllText($wslcLog, $wslcLine + "`n", $wslcUtf8)
    $wslcSavedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & cargo @CargoArgs 2>&1 | ForEach-Object {
            $wslcLine = $_.ToString()
            [IO.File]::AppendAllText($wslcLog, $wslcLine + "`n", $wslcUtf8)
            Write-Host $wslcLine
        }
        $wslcCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $wslcSavedPreference }
    if ($wslcCode -ne 0) { throw "cargo failed (exit $wslcCode); see $wslcLog" }
}

function Get-CliText([string]$Cli, [string[]]$CliArgs) {
    # `wsl.exe` emits UTF-16LE when piped; `wslc` emits UTF-8. Let the
    # console decode, then strip embedded NULs — a bare `Out-String`
    # over UTF-16LE yields one char per byte and no regex would match.
    $wslcRaw = try { (& $Cli @CliArgs 2>$null | Out-String) } catch { return $null }
    return ($wslcRaw -replace "`0", '')
}

function Get-WslVersionTriple {
    $wslcWslText = Get-CliText 'wsl.exe' @('--version')
    if ($null -eq $wslcWslText) { return $null }
    foreach ($wslcL in ($wslcWslText -split "`r?`n")) {
        if ($wslcL -match 'WSL version\D+(\d+)\.(\d+)\.(\d+)') {
            return [version]("$($Matches[1]).$($Matches[2]).$($Matches[3])")
        }
    }
    return $null
}

try {
    # Host identity first — an environment-gate failure still records
    # what the run ran on, matching the other validate-* jobs.
    $wslcResult.commit = try { (& git rev-parse HEAD).Trim() } catch { 'unknown' }
    $wslcResult.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    $wslcResult.os_revision = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    $wslcResult.architecture = $env:PROCESSOR_ARCHITECTURE
    $wslcResult.session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $wslcResult.user_interactive = [Environment]::UserInteractive
    $wslcResult.elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $wslcResult.rustc = try { (& rustc --version).Trim() } catch { 'unavailable' }
    $wslcResult.wsl_version_text = $( $wslcT = Get-CliText 'wsl.exe' @('--version'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    $wslcResult.wslc_version_text = $( $wslcT = Get-CliText 'wslc' @('--version'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    $wslcResult.wsl_distros = $( $wslcT = Get-CliText 'wsl.exe' @('-l', '-v'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    $wslcResult.wslc_sessions_before = $( $wslcT = Get-CliText 'wslc' @('system', 'session', 'list'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )

    $wslcMetadata = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $wslcDrives = @(
        [IO.Path]::GetPathRoot($wslcMetadata.target_directory),
        [IO.Path]::GetPathRoot($env:TEMP),
        [IO.Path]::GetPathRoot($env:LOCALAPPDATA),
        [IO.Path]::GetPathRoot($wslcSessionRoot)
    ) | Select-Object -Unique
    if (@($wslcDrives | Where-Object { ([IO.DriveInfo]::new($_)).AvailableFreeSpace -lt 40GB }).Count -gt 0) {
        Invoke-WslcCargo @('clean')
    }
    foreach ($wslcDrive in $wslcDrives) {
        $wslcFree = ([IO.DriveInfo]::new($wslcDrive)).AvailableFreeSpace
        if ($wslcFree -lt 40GB) { throw "$wslcDrive has less than 40 GiB free after cargo clean" }
    }

    # ── Environment gate — 'environment-unavailable' ends here ─────
    $wslcEnvFail = $null
    if ($wslcResult.architecture -ne 'AMD64') { $wslcEnvFail = 'PR-28 validates Windows x86-64 first' }
    if (-not $wslcEnvFail -and $wslcResult.session_id -eq 0) { $wslcEnvFail = 'Session 0 (non-interactive service) — wslc needs an interactive logon session' }
    if (-not $wslcEnvFail) {
        $wslcWsl = Get-WslVersionTriple
        if ($null -eq $wslcWsl) { $wslcEnvFail = 'could not parse `wsl.exe --version`' }
        elseif ($wslcWsl -lt [version]'2.9.3') { $wslcEnvFail = "WSL $wslcWsl is below the documented wslc floor 2.9.3 — this script never runs 'wsl --update'" }
    }
    if (-not $wslcEnvFail -and $wslcResult.wslc_version_text -eq 'unavailable') { $wslcEnvFail = 'no `wslc` CLI on PATH' }
    if (-not $wslcEnvFail -and $wslcResult.wslc_version_text -eq '') { $wslcEnvFail = '`wslc --version` produced no output' }
    if (-not $wslcEnvFail -and $wslcResult.rustc -eq 'unavailable') { $wslcEnvFail = 'rustc is not on PATH' }
    if (-not $wslcEnvFail) {
        # `rustc --print target-list` lists every *supported* target —
        # musl is always in it, so it cannot gate installation. Prefer
        # rustup's installed-target list; without rustup, the target's
        # libdir under the sysroot exists iff the std component is
        # installed.
        $wslcMuslInstalled = $false
        if ($null -ne (Get-Command rustup -ErrorAction SilentlyContinue)) {
            $wslcMuslInstalled = (@(& rustup target list --installed 2>$null | ForEach-Object { $_.Trim() }) -contains 'x86_64-unknown-linux-musl')
        } else {
            $wslcLibdir = (& rustc --print target-libdir --target x86_64-unknown-linux-musl 2>$null | Out-String).Trim()
            $wslcMuslInstalled = ($LASTEXITCODE -eq 0 -and $wslcLibdir -ne '' -and (Test-Path -LiteralPath $wslcLibdir -PathType Container))
        }
        if (-not $wslcMuslInstalled) { $wslcEnvFail = 'rust target x86_64-unknown-linux-musl is not installed' }
    }
    if ($wslcEnvFail) {
        $wslcResult.result = 'environment-unavailable'
        $wslcResult.environment_failure = $wslcEnvFail
        throw "environment unavailable: $wslcEnvFail"
    }

    $env:TEMP = $wslcWork
    $env:TMP = $wslcWork
    $env:CARGO_INCREMENTAL = '0'
    $env:MCP_WRIT_REQUIRE_WSLC_TESTS = '1'
    $env:MCP_WRIT_WSLC_TEST_ROOT = $wslcWork
    $env:MCP_WRIT_WSLC_EVIDENCE_DIR = $wslcEvidence
    $env:MCP_WRIT_WSLC_SESSION_ROOT = $wslcSessionRoot
    $wslcResult.source_hashes = @(
        Get-Item -LiteralPath 'src/container/windows_probe.rs', 'src/container/engine.rs', 'src/container/guest_report.rs', 'src/bin/mcp-secure-runner.rs', 'scripts/validate-wslc.ps1'
        Get-ChildItem -LiteralPath 'tests/wslc_container_e2e' -File -Filter '*.rs'
        Get-Item -LiteralPath 'tests/common/mod.rs'
        Get-ChildItem -LiteralPath 'tests/fixtures/wslc' -File
    ) | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash

    for ($wslcIteration = 1; $wslcIteration -le $Repetitions; $wslcIteration++) {
        $wslcArgs = @('test', '--locked', '--test', 'wslc_container_e2e')
        if ($wslcIteration -gt 1) {
            # Repeat only the measured runner-wrapped session; discovery
            # and semantics legs run once.
            $wslcArgs += 'wslc_stdio_session'
        }
        $wslcArgs += @('--', '--nocapture')
        Invoke-WslcCargo $wslcArgs
    }

    # Evidence accounting — the measured session dir must carry the
    # guest report + audit trail; the lifecycle/session dirs must exist.
    $wslcMetrics = @(Get-ChildItem -LiteralPath $wslcEvidence -Filter 'metrics.json' -Recurse -File |
        Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).tier -eq 'harness' })
    if ($wslcMetrics.Count -ne $Repetitions) { throw 'Measured session evidence is missing' }
    foreach ($wslcMetric in $wslcMetrics) {
        foreach ($wslcRequiredFile in @('report\report.json', 'logs\audit.jsonl')) {
            $wslcRequiredPath = Join-Path $wslcMetric.DirectoryName $wslcRequiredFile
            if (-not (Test-Path -LiteralPath $wslcRequiredPath -PathType Leaf)) { throw "Evidence missing: $wslcRequiredPath" }
        }
    }
    $wslcLifecycles = @(Get-ChildItem -LiteralPath $wslcEvidence -Filter 'lifecycle.json' -Recurse -File)
    if ($wslcLifecycles.Count -lt 3) { throw 'Lifecycle evidence is missing (session-model, stop, cli-death)' }
    foreach ($wslcRecord in @('host-identity.json', 'capability-map.json', 'stdio-contract.json', 'session-model.json', 'share-semantics.json', 'network-semantics.json', 'storage.json')) {
        $wslcFound = @(Get-ChildItem -LiteralPath $wslcEvidence -Filter $wslcRecord -Recurse -File)
        if ($wslcFound.Count -lt 1) { throw "Environment/semantics evidence missing: $wslcRecord" }
    }
    $wslcResult.result = 'wslc-tests-passed'
} catch {
    $wslcResult.error = $_.ToString()
    throw
} finally {
    $wslcResult.finished_utc = [DateTime]::UtcNow.ToString('o')
    # Session inventory after the run — an owned-session leak or a
    # disturbed foreign session is recorded, never silently fixed.
    $wslcResult.wslc_sessions_after = $( $wslcT = Get-CliText 'wslc' @('system', 'session', 'list'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    $wslcResult.wsl_units_after = $( $wslcT = Get-CliText 'wslc' @('list', '-a'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    $wslcResult.wsl_distros_after = $( $wslcT = Get-CliText 'wsl.exe' @('-l', '-v'); if ($null -eq $wslcT) { 'unavailable' } else { $wslcT.Trim() } )
    foreach ($wslcVar in $wslcVars) { [Environment]::SetEnvironmentVariable($wslcVar, $wslcOldEnv[$wslcVar], 'Process') }
    # Delete only this invocation's verified work directory — the
    # session VHDs under session-storage go with it. Evidence stays.
    $wslcResolvedWork = [IO.Path]::GetFullPath($wslcWork)
    $wslcResolvedRun = [IO.Path]::GetFullPath($wslcRun) + [IO.Path]::DirectorySeparatorChar
    if (-not $wslcResolvedWork.StartsWith($wslcResolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside this validation run'
    }
    $wslcCleanupFailed = $false
    try { Remove-Item -LiteralPath $wslcResolvedWork -Recurse -Force; $wslcResult.work_cleanup = 'passed' }
    catch { $wslcResult.work_cleanup = $_.ToString(); $wslcResult.result = 'failed'; $wslcCleanupFailed = $true; Write-Warning $_ }
    [IO.File]::WriteAllText((Join-Path $wslcRun 'result.json'), ($wslcResult | ConvertTo-Json -Depth 6) + "`n", $wslcUtf8)
    Pop-Location
    Write-Host "Validation record: $wslcRun"
    if ($wslcCleanupFailed) { throw 'Validation work directory cleanup failed' }
}
