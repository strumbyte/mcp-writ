# Exercise the same handle-based ACL code on a private file without admin
# rights. -IncludeDevice also checks the real NUL wrapper on elevated CI.
[CmdletBinding()]
param([switch]$IncludeDevice)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot)
Add-Type -Path (Join-Path $repo 'scripts/lib/windows-null-device.cs')

function Get-DaclBytes([string]$Path) {
    # Read by handle, including for device objects.
    $type = [McpWrit.Ci.NullDeviceAccess]
    $flags = [System.Reflection.BindingFlags]'NonPublic,Static'
    $openArgs = [object[]]@($Path, [uint32]0x20000, [uint32]3,
        [IntPtr]::Zero, [uint32]3, [uint32]0x02000000, [IntPtr]::Zero)
    $handle = $type.GetMethod('CreateFileW', $flags).Invoke($null, $openArgs)
    if ($handle.IsInvalid) { throw "Cannot read DACL: $Path" }
    $query = [object[]]@($handle, 1, [uint32]4, [IntPtr]::Zero,
        [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    try {
        $errorCode = $type.GetMethod('GetSecurityInfo', $flags).Invoke($null, $query)
        if ($errorCode -ne 0) { throw "GetSecurityInfo failed: $errorCode" }
        $length = $type.GetMethod('GetSecurityDescriptorLength', $flags).Invoke($null, @($query[7]))
        $bytes = [byte[]]::new($length)
        [Runtime.InteropServices.Marshal]::Copy($query[7], $bytes, 0, $bytes.Length)
        $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
        $acl = [byte[]]::new($sd.DiscretionaryAcl.BinaryLength)
        $sd.DiscretionaryAcl.GetBinaryForm($acl, 0)
        return ,$acl
    } finally {
        if ($query[7] -ne [IntPtr]::Zero) {
            $null = $type.GetMethod('LocalFree', $flags).Invoke($null, @($query[7]))
        }
        $handle.Dispose()
    }
}

function Assert-Restored([string]$Path, [byte[]]$Before) {
    $after = Get-DaclBytes $Path
    if ([Convert]::ToBase64String($after) -cne [Convert]::ToBase64String($Before)) {
        $oldAcl = [System.Security.AccessControl.RawAcl]::new($Before, 0)
        $newAcl = [System.Security.AccessControl.RawAcl]::new($after, 0)
        $describe = { param($acl) @($acl | ForEach-Object { "$($_.SecurityIdentifier.Value):$($_.AceFlags):$($_.AccessMask)" }) }
        $delta = Compare-Object (& $describe $oldAcl) (& $describe $newAcl) | Out-String
        throw "DACL was not restored exactly: $Path`n$delta"
    }
}

$file = Join-Path ([IO.Path]::GetTempPath()) ('mcp-writ-null-acl-' + [guid]::NewGuid() + '.txt')
[IO.File]::WriteAllText($file, 'private ACL fixture', [Text.UTF8Encoding]::new($false))
try {
    $before = Get-DaclBytes $file
    $access = [McpWrit.Ci.NullDeviceAccess]::Grant($file)
    try {
        $acl = [System.Security.AccessControl.RawAcl]::new((Get-DaclBytes $file), 0)
        $grants = @($acl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-15-2-1' })
        if ($grants.Count -ne 1 -or $grants[0].AccessMask -ne 0x12019f -or
            $grants[0].AceFlags -ne 0 -or $grants[0].AceQualifier -ne 'AccessAllowed') {
            throw 'Expected only non-inherited AppContainer read/write access'
        }
    } finally { $access.Dispose() }
    Assert-Restored $file $before
    $access.Dispose() # teardown is idempotent
    Assert-Restored $file $before
    Write-Output 'PASS: scoped read/write grant and exact, idempotent DACL restore'

    $directory = $file + '.dir'
    $child = Join-Path $directory 'child.txt'
    $null = New-Item -ItemType Directory -Path $directory
    [IO.File]::WriteAllText($child, 'must not inherit the grant', [Text.UTF8Encoding]::new($false))
    try {
        $directoryBefore = Get-DaclBytes $directory
        $childBefore = Get-DaclBytes $child
        $access = [McpWrit.Ci.NullDeviceAccess]::GrantDirectoryMetadata($directory)
        try {
            $acl = [System.Security.AccessControl.RawAcl]::new((Get-DaclBytes $directory), 0)
            $grants = @($acl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-15-2-1' })
            if ($grants.Count -ne 1 -or $grants[0].AccessMask -ne 0x1000a1 -or
                $grants[0].AceFlags -ne 0 -or $grants[0].AceQualifier -ne 'AccessAllowed') {
                throw 'Expected only non-inherited directory list/traverse/attribute/synchronize access'
            }
            Assert-Restored $child $childBefore
        } finally { $access.Dispose() }
        Assert-Restored $directory $directoryBefore
        Assert-Restored $child $childBefore
        Write-Output 'PASS: directory metadata grant does not propagate; exact DACL restore'
    } finally {
        Remove-Item -LiteralPath $child -Force
        Remove-Item -LiteralPath $directory -Force
    }

    if ($IncludeDevice) {
        $before = Get-DaclBytes '\\.\NUL'
        $wrapper = Join-Path $repo 'scripts/with-windows-null-device.ps1'
        $ancestors = @()
        $directory = [IO.DirectoryInfo]::new([IO.Path]::GetTempPath())
        while ($null -ne $directory) {
            $ancestors += @{ Path = $directory.FullName; Before = (Get-DaclBytes $directory.FullName) }
            $directory = $directory.Parent
        }
        & $wrapper -IncludeTempAncestors -Command { Write-Output 'success path' }
        Assert-Restored '\\.\NUL' $before
        foreach ($ancestor in $ancestors) { Assert-Restored $ancestor.Path $ancestor.Before }
        $caught = $false
        try { & $wrapper -IncludeTempAncestors -Command { throw 'intentional test failure' } }
        catch {
            if ($_.Exception.Message -ne 'intentional test failure') { throw }
            $caught = $true
        }
        if (-not $caught) { throw 'Wrapper swallowed command failure' }
        Assert-Restored '\\.\NUL' $before
        foreach ($ancestor in $ancestors) { Assert-Restored $ancestor.Path $ancestor.Before }
        Write-Output 'PASS: real NUL and ancestor DACLs restored on success and command failure'
    }
} finally {
    Remove-Item -LiteralPath $file -Force
}
