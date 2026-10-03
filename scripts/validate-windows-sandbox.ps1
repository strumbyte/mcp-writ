# PR-23 validation. Run in a normal interactive PowerShell session.
# -Vm requires an enabled Sandbox and the wsb CLI with instance IDs.
[CmdletBinding()]
param(
    [switch]$Vm,
    [ValidateRange(1, 10)][int]$Repetitions = 1
)

$ErrorActionPreference = 'Stop'
$wsbRepo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$wsbUtf8 = [Text.UTF8Encoding]::new($false)
$wsbRun = Join-Path $wsbRepo ('.local\wsb-validation\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
$wsbWork = Join-Path $wsbRun 'work'
$wsbEvidence = Join-Path $wsbRun 'evidence'
$wsbLog = Join-Path $wsbRun 'test-output.txt'
$wsbVars = @('TEMP', 'TMP', 'CARGO_INCREMENTAL', 'MCP_WRIT_REQUIRE_WSB_TESTS', 'MCP_WRIT_WSB_TEST_ROOT', 'MCP_WRIT_WSB_EVIDENCE_DIR')
$wsbOldEnv = @{}
foreach ($wsbVar in $wsbVars) { $wsbOldEnv[$wsbVar] = [Environment]::GetEnvironmentVariable($wsbVar, 'Process') }
New-Item -ItemType Directory -Path $wsbWork, $wsbEvidence -Force | Out-Null
$wsbResult = @{ vm_requested = [bool]$Vm; repetitions = $Repetitions; result = 'failed'; started_utc = [DateTime]::UtcNow.ToString('o') }
Push-Location $wsbRepo

function Invoke-WsbCargo([string[]]$CargoArgs) {
    $wsbLine = 'cargo ' + ($CargoArgs -join ' ')
    Write-Host $wsbLine
    [IO.File]::AppendAllText($wsbLog, $wsbLine + "`n", $wsbUtf8)
    $wsbSavedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & cargo @CargoArgs 2>&1 | ForEach-Object {
            $wsbLine = $_.ToString()
            [IO.File]::AppendAllText($wsbLog, $wsbLine + "`n", $wsbUtf8)
            Write-Host $wsbLine
        }
        $wsbCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $wsbSavedPreference }
    if ($wsbCode -ne 0) { throw "cargo failed (exit $wsbCode); see $wsbLog" }
}

try {
    $wsbMetadata = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $wsbDrives = @([IO.Path]::GetPathRoot($wsbMetadata.target_directory), [IO.Path]::GetPathRoot($env:TEMP)) | Select-Object -Unique
    if (@($wsbDrives | Where-Object { ([IO.DriveInfo]::new($_)).AvailableFreeSpace -lt 40GB }).Count -gt 0) {
        Invoke-WsbCargo @('clean')
    }
    foreach ($wsbDrive in $wsbDrives) {
        $wsbFree = ([IO.DriveInfo]::new($wsbDrive)).AvailableFreeSpace
        if ($wsbFree -lt 40GB) { throw "$wsbDrive has less than 40 GiB free after cargo clean" }
    }
    $env:TEMP = $wsbWork
    $env:TMP = $wsbWork
    $env:CARGO_INCREMENTAL = '0'
    $env:MCP_WRIT_REQUIRE_WSB_TESTS = '1'
    $env:MCP_WRIT_WSB_TEST_ROOT = $wsbWork
    $env:MCP_WRIT_WSB_EVIDENCE_DIR = $wsbEvidence
    $wsbResult.commit = (& git rev-parse HEAD).Trim()
    $wsbResult.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    $wsbResult.os_revision = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    $wsbResult.architecture = $env:PROCESSOR_ARCHITECTURE
    $wsbResult.session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $wsbResult.rustc = (& rustc --version).Trim()
    $wsbResult.source_hashes = @(
        Get-Item -LiteralPath 'src/pathutil.rs', 'scripts/validate-windows-sandbox.ps1'
        Get-Item -LiteralPath 'tests/windows_sandbox_vm_e2e.rs'
        Get-ChildItem -LiteralPath 'tests/fixtures/windows_sandbox' -File
    ) | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash
    if ($Vm) {
        $wsbCli = $(if ($env:MCP_WRIT_WSB_EXE) { $env:MCP_WRIT_WSB_EXE } else { 'wsb.exe' })
        $wsbResult.wsb_version = (& $wsbCli --version).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'wsb --version failed' }
    }
    for ($wsbIteration = 1; $wsbIteration -le $Repetitions; $wsbIteration++) {
        $wsbArgs = @('test', '--locked', '--test', 'windows_sandbox_vm_e2e')
        if ($wsbIteration -gt 1) {
            # Repeat the measured real-runner session; adverse cases run once.
            $wsbArgs += $(if ($Vm) { 'wsb_relay_stdio_session' } else { 'wsb_relay_loopback_protocol' })
        }
        $wsbArgs += @('--', '--nocapture')
        if (-not $Vm) { $wsbArgs += @('--skip', 'wsb_relay_stdio_session', '--skip', 'wsb_relay_sandbox') }
        Invoke-WsbCargo $wsbArgs
    }
    $wsbTier = $(if ($Vm) { 'vm' } else { 'loopback' })
    $wsbMetrics = @(Get-ChildItem -LiteralPath $wsbEvidence -Filter 'metrics.json' -Recurse -File |
        Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).tier -eq $wsbTier })
    if ($wsbMetrics.Count -ne $Repetitions) { throw 'Measured session evidence is missing' }
    foreach ($wsbMetric in $wsbMetrics) {
        $wsbRequiredFiles = @('report\report.json', 'logs\audit.jsonl')
        if ($Vm) { $wsbRequiredFiles += @('guest-identity.json', 'lifecycle.json', 'host-memory-before.json', 'host-memory-during.json', 'host-memory-after.json') }
        foreach ($wsbRequiredFile in $wsbRequiredFiles) {
            $wsbRequiredPath = Join-Path $wsbMetric.DirectoryName $wsbRequiredFile
            if (-not (Test-Path -LiteralPath $wsbRequiredPath -PathType Leaf)) { throw "Evidence missing: $wsbRequiredPath" }
        }
    }
    $wsbResult.result = $(if ($Vm) { 'vm-tests-passed-review-metrics-before-adoption' } else { 'local-tests-passed-vm-unexecuted' })
} catch {
    $wsbResult.error = $_.ToString()
    throw
} finally {
    $wsbResult.finished_utc = [DateTime]::UtcNow.ToString('o')
    foreach ($wsbVar in $wsbVars) { [Environment]::SetEnvironmentVariable($wsbVar, $wsbOldEnv[$wsbVar], 'Process') }
    # Delete only this invocation's verified work directory. Evidence stays.
    $wsbResolvedWork = [IO.Path]::GetFullPath($wsbWork)
    $wsbResolvedRun = [IO.Path]::GetFullPath($wsbRun) + [IO.Path]::DirectorySeparatorChar
    if (-not $wsbResolvedWork.StartsWith($wsbResolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside this validation run'
    }
    $wsbCleanupFailed = $false
    try { Remove-Item -LiteralPath $wsbResolvedWork -Recurse -Force; $wsbResult.work_cleanup = 'passed' }
    catch { $wsbResult.work_cleanup = $_.ToString(); $wsbResult.result = 'failed'; $wsbCleanupFailed = $true; Write-Warning $_ }
    [IO.File]::WriteAllText((Join-Path $wsbRun 'result.json'), ($wsbResult | ConvertTo-Json -Depth 6) + "`n", $wsbUtf8)
    Pop-Location
    Write-Host "Validation record: $wsbRun"
    if ($wsbCleanupFailed) { throw 'Validation work directory cleanup failed' }
}
