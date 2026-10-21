# Run a test command with AppContainer read/write access to the NUL device.
# Intended for an isolated, elevated Windows CI runner. NUL has no stored
# data; this grants no filesystem, network, execute, or ACL-writing rights.
# Restore the exact original DACL even when the command throws.
[CmdletBinding()]
param([Parameter(Mandatory)][scriptblock]$Command)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This helper requires Windows.' }

if (-not ('McpWrit.Ci.NullDeviceAccess' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'lib/windows-null-device.cs')
}

$nullAccess = [McpWrit.Ci.NullDeviceAccess]::Grant('\\.\NUL')
try {
    Write-Output 'CI prerequisite: AppContainer NUL read/write granted for this command.'
    & $Command
} finally {
    $nullAccess.Dispose()
    Write-Output 'CI prerequisite: original NUL DACL restored.'
}
