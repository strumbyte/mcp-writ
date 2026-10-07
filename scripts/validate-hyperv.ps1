# PR-20/25 Hyper-V isolated-container validation job. Run in a normal
# interactive PowerShell session on a Windows x86-64 host meeting the
# environment in docs/validation/windows-hyperv.md: a Windows-mode
# Docker engine (OSType=windows), Hyper-V enabled, the pinned Server
# Core base image pullable, and rustc. Produces an evidence bundle under
# .local\hyperv-validation\<utc>-<guid>\ and exits non-zero when the
# environment, the tests, or the evidence is missing — an unexecuted or
# unevidenced run is never a pass.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$hvRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$hvUtf8 = [Text.UTF8Encoding]::new($false)
$hvRun = Join-Path $hvRepo ('.local\hyperv-validation\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
$hvWork = Join-Path $hvRun 'work'
$hvEvidence = Join-Path $hvRun 'evidence'
$hvLog = Join-Path $hvRun 'test-output.txt'
$hvVars = @('TEMP', 'TMP', 'CARGO_INCREMENTAL', 'MCP_WRIT_REQUIRE_HYPERV_TESTS', 'MCP_WRIT_HYPERV_TEST_ROOT', 'MCP_WRIT_HYPERV_EVIDENCE_DIR')
$hvOldEnv = @{}
foreach ($hvVar in $hvVars) { $hvOldEnv[$hvVar] = [Environment]::GetEnvironmentVariable($hvVar, 'Process') }
New-Item -ItemType Directory -Path $hvWork, $hvEvidence -Force | Out-Null
$hvResult = @{ vm_requested = $true; result = 'failed'; started_utc = [DateTime]::UtcNow.ToString('o') }
Push-Location $hvRepo

function Invoke-HvCargo([string[]]$CargoArgs) {
    $hvLine = 'cargo ' + ($CargoArgs -join ' ')
    Write-Host $hvLine
    [IO.File]::AppendAllText($hvLog, $hvLine + "`n", $hvUtf8)
    $hvSavedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & cargo @CargoArgs 2>&1 | ForEach-Object {
            $hvLine = $_.ToString()
            [IO.File]::AppendAllText($hvLog, $hvLine + "`n", $hvUtf8)
            Write-Host $hvLine
        }
        $hvCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $hvSavedPreference }
    return $hvCode
}

try {
    # Host identity first — an environment-gate failure still records
    # what the run ran on, mirroring validate-kata.sh's emit-at-failure.
    $hvResult.commit = try { (& git rev-parse HEAD).Trim() } catch { 'unknown' }
    $hvResult.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    $hvResult.os_revision = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    $hvResult.architecture = $env:PROCESSOR_ARCHITECTURE
    $hvResult.session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $hvResult.rustc = try { (& rustc --version).Trim() } catch { 'unavailable' }

    # ── environment gate — fail closed before any test work ──────────
    $hvOsType = (& docker info --format '{{.OSType}}' 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'docker engine is not reachable' }
    if ($hvOsType -ne 'windows') { throw "docker OSType is '$hvOsType' - switch the engine to Windows containers" }
    $hvResult.docker = @{
        server = (& docker info --format '{{.ServerVersion}}' 2>$null).Trim()
        client = (& docker version --format '{{.Client.Version}}' 2>$null).Trim()
        ostype = $hvOsType
    }
    if (-not ([Environment]::Is64BitOperatingSystem -and $env:PROCESSOR_ARCHITECTURE -eq 'AMD64')) {
        throw 'the host must be Windows x86-64'
    }
    if ($hvResult.rustc -eq 'unavailable') { throw 'rustc is not on PATH (probe compile)' }
    $hvMetadata = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $hvDrives = @([IO.Path]::GetPathRoot($hvMetadata.target_directory), [IO.Path]::GetPathRoot($env:TEMP)) | Select-Object -Unique
    if (@($hvDrives | Where-Object { ([IO.DriveInfo]::new($_)).AvailableFreeSpace -lt 40GB }).Count -gt 0) {
        if ((Invoke-HvCargo @('clean')) -ne 0) { throw 'cargo clean failed' }
    }
    foreach ($hvDrive in $hvDrives) {
        $hvFree = ([IO.DriveInfo]::new($hvDrive)).AvailableFreeSpace
        if ($hvFree -lt 40GB) { throw "$hvDrive has less than 40 GiB free after cargo clean" }
    }
    $env:TEMP = $hvWork
    $env:TMP = $hvWork
    $env:CARGO_INCREMENTAL = '0'
    $env:MCP_WRIT_REQUIRE_HYPERV_TESTS = '1'
    $env:MCP_WRIT_HYPERV_TEST_ROOT = $hvWork
    $env:MCP_WRIT_HYPERV_EVIDENCE_DIR = $hvEvidence
    $hvResult.source_hashes = @(
        Get-Item -LiteralPath 'tests/hyperv_vm_e2e.rs', 'scripts/validate-hyperv.ps1', 'src/container/backends/hyperv.rs', 'src/bin/mcp-secure-runner.rs'
        Get-ChildItem -LiteralPath 'tests/fixtures/hyperv' -File
    ) | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash

    # ── enumerate the suite — the count gate below compares the run
    #    against the binary's own `--list`, never a hardcoded number
    #    that silently rots when a leg is added ─────────────────────
    $hvListCode = Invoke-HvCargo @('test', '--locked', '--test', 'hyperv_vm_e2e', '--', '--list')
    if ($hvListCode -ne 0) { throw "cargo test --list failed (exit $hvListCode); see $hvLog" }
    $hvExpected = @([IO.File]::ReadAllLines($hvLog) | Where-Object { $_ -match '^\S+: test$' }).Count
    if ($hvExpected -lt 1) { throw 'test enumeration listed no tests - the count gate cannot verify a run it cannot count' }

    # ── run the gated suite — the env vars make unexecuted legs fail ──
    $hvCode = Invoke-HvCargo @('test', '--locked', '--test', 'hyperv_vm_e2e', '--', '--nocapture')
    $hvLogText = [IO.File]::ReadAllText($hvLog)
    $hvPassed = 0; $hvFailed = 0; $hvIgnored = 0
    foreach ($hvMatch in [regex]::Matches($hvLogText, 'test result:.*')) {
        if ($hvMatch.Value -match '(\d+) passed') { $hvPassed += [int]$Matches[1] }
        if ($hvMatch.Value -match '(\d+) failed') { $hvFailed += [int]$Matches[1] }
        if ($hvMatch.Value -match '(\d+) ignored') { $hvIgnored += [int]$Matches[1] }
    }
    $hvResult.tests = @{ passed = $hvPassed; failed = $hvFailed; ignored = $hvIgnored; expected = $hvExpected }
    if ($hvCode -ne 0 -or $hvFailed -gt 0) { throw "hyperv_vm_e2e failed: $hvPassed passed, $hvFailed failed (see $hvLog)" }
    if ($hvPassed -ne $hvExpected -or $hvIgnored -gt 0) { throw "expected all $hvExpected enumerated hyperv tests executed, got passed=$hvPassed ignored=$hvIgnored - an unexecuted leg is not a pass" }

    # ── evidence completeness — a pass without its record is not a pass ──
    $hvMetrics = @(Get-ChildItem -LiteralPath $hvEvidence -Filter 'metrics.json' -Recurse -File)
    if ($hvMetrics.Count -ne 2) { throw "expected 2 session metrics records, got $($hvMetrics.Count)" }
    foreach ($hvMetric in $hvMetrics) {
        foreach ($hvFile in @('report\report.json', 'logs\audit.jsonl')) {
            if (-not (Test-Path -LiteralPath (Join-Path $hvMetric.DirectoryName $hvFile) -PathType Leaf)) { throw "Evidence missing: $hvFile" }
        }
        $hvTier = (Get-Content -LiteralPath $hvMetric.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).tier
        if ($hvTier -eq 'product') {
            foreach ($hvFile in @('host-identity.json', 'report\host-launch-report.json')) {
                if (-not (Test-Path -LiteralPath (Join-Path $hvMetric.DirectoryName $hvFile) -PathType Leaf)) { throw "Product evidence missing: $hvFile" }
            }
        }
    }
    $hvLifecycle = @(Get-ChildItem -LiteralPath $hvEvidence -Filter 'lifecycle.json' -Recurse -File)
    if ($hvLifecycle.Count -ne 6) { throw "expected 6 lifecycle records, got $($hvLifecycle.Count)" }
    $hvResult.evidence = @{ metrics = $hvMetrics.Count; lifecycle = $hvLifecycle.Count; dir = $hvEvidence }

    # ── image + guest versions for the record ────────────────────────
    $hvBase = (Select-String -LiteralPath 'tests\hyperv_vm_e2e.rs' -Pattern 'windows/servercore@sha256:[a-f0-9]+').Matches.Value | Select-Object -First 1
    $hvResult.images = @{
        base    = $hvBase
        probe   = (& docker image inspect 'mcp-writ-hyperv-probe:test' --format '{{.Id}}' 2>$null)
        wrapped = (& docker image inspect 'mcp-writ-hyperv-wrapped:test' --format '{{.Id}}' 2>$null)
    }

    $hvResult.result = 'vm-tests-passed'
} catch {
    $hvResult.error = $_.ToString()
    throw
} finally {
    $hvResult.finished_utc = [DateTime]::UtcNow.ToString('o')
    foreach ($hvVar in $hvVars) { [Environment]::SetEnvironmentVariable($hvVar, $hvOldEnv[$hvVar], 'Process') }
    # Delete only this invocation's verified work directory. Evidence stays.
    $hvResolvedWork = [IO.Path]::GetFullPath($hvWork)
    $hvResolvedRun = [IO.Path]::GetFullPath($hvRun) + [IO.Path]::DirectorySeparatorChar
    if (-not $hvResolvedWork.StartsWith($hvResolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside this validation run'
    }
    $hvCleanupFailed = $false
    try { Remove-Item -LiteralPath $hvResolvedWork -Recurse -Force; $hvResult.work_cleanup = 'passed' }
    catch { $hvResult.work_cleanup = $_.ToString(); $hvResult.result = 'failed'; $hvCleanupFailed = $true; Write-Warning $_ }
    [IO.File]::WriteAllText((Join-Path $hvRun 'result.json'), ($hvResult | ConvertTo-Json -Depth 6) + "`n", $hvUtf8)
    Pop-Location
    Write-Host "Validation record: $hvRun"
    if ($hvCleanupFailed) { throw 'Validation work directory cleanup failed' }
}
