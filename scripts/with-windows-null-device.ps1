# Run a test command with AppContainer read/write access to the NUL device.
# Intended for an isolated, elevated Windows CI runner. NUL has no stored
# data. IncludeTempAncestors also grants non-inherited directory metadata
# access along the temporary path, without file content or write access.
# Restore the exact original DACL even when the command throws.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][scriptblock]$Command,
    [switch]$IncludeTempAncestors
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This helper requires Windows.' }

if (-not ('McpWrit.Ci.NullDeviceAccess' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'lib/windows-null-device.cs')
}

$grants = [System.Collections.Generic.List[System.IDisposable]]::new()
try {
    $grants.Add([McpWrit.Ci.NullDeviceAccess]::Grant('\\.\NUL'))
    Write-Output 'CI prerequisite: AppContainer NUL read/write granted for this command.'
    if ($IncludeTempAncestors) {
        # Git's GetLongPathNameW fallback needs parent directory enumeration.
        # No inheritance, file data access, or recursive ACL propagation.
        $directory = [IO.DirectoryInfo]::new([IO.Path]::GetTempPath())
        while ($null -ne $directory) {
            $grants.Add([McpWrit.Ci.NullDeviceAccess]::GrantDirectoryMetadata($directory.FullName))
            Write-Output "CI prerequisite: directory metadata granted on $($directory.FullName)"
            $directory = $directory.Parent
        }
    }
    $global:LASTEXITCODE = $null
    & $Command
    if ($LASTEXITCODE) { throw "Command failed with exit code $LASTEXITCODE" }
} finally {
    $restoreErrors = @()
    for ($index = $grants.Count - 1; $index -ge 0; $index--) {
        try { $grants[$index].Dispose() }
        catch { $restoreErrors += $_ }
    }
    if ($restoreErrors.Count) { throw $restoreErrors[0] }
    Write-Output 'CI prerequisite: original device and directory DACLs restored.'
}
