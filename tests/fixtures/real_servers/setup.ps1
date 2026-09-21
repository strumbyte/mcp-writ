# Fetch the pinned real MCP servers used by tests/real_servers_e2e.rs.
# No arguments. Idempotent: skips each runtime that is already installed.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Node: package-lock.json is committed; npm ci reproduces it exactly.
if (Test-Path node\node_modules) {
    Write-Output 'setup: node already installed (node/node_modules present)'
} else {
    Push-Location node
    try {
        npm ci --ignore-scripts
    } finally {
        Pop-Location
    }
    Write-Output 'setup: node installed'
}

# Python: requirements.txt pins every artifact by sha256. A venv counts as
# installed only when the marker written after a successful pip install is
# present — a leftover from an interrupted run is removed and recreated.
if (Test-Path python\.venv\.install-complete) {
    Write-Output 'setup: python already installed (python/.venv present)'
} else {
    if (Test-Path python\.venv) {
        Remove-Item -Recurse -Force python\.venv
    }
    # CI runners may lack the `py` launcher; fall back to PATH python.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        py -3 -m venv python\.venv
    } else {
        python -m venv python\.venv
    }
    python\.venv\Scripts\pip.exe install --require-hashes -r python\requirements.txt
    # $ErrorActionPreference does not apply to native exit codes; a failed
    # pip install must not leave the completion marker behind.
    if ($LASTEXITCODE -ne 0) { throw "setup: pip install failed ($LASTEXITCODE)" }
    New-Item -ItemType File -Path python\.venv\.install-complete | Out-Null
    Write-Output 'setup: python installed'
}

# MinGit: the sandboxed git subprocess needs a grantable executable — a
# system git under Program Files is neither DACL-grantable by a non-admin
# nor covered by package ACEs. Pinned archive, verified by sha256.
$mingitVersion = '2.55.0.4'
$mingitSha256 = '4e03f94c2ffbf70be337e005cee02661c732dbfc81031a078bda9299b9a7d644'
if (Test-Path mingit\cmd\git.exe) {
    Write-Output 'setup: mingit already installed (mingit/cmd/git.exe present)'
} else {
    $zip = Join-Path $env:TEMP "MinGit-$mingitVersion-64-bit.zip"
    Invoke-WebRequest `
        -Uri "https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.4/MinGit-$mingitVersion-64-bit.zip" `
        -OutFile $zip
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $mingitSha256) {
        Remove-Item $zip -Force
        throw "setup: mingit sha256 mismatch: expected $mingitSha256, got $actual"
    }
    Expand-Archive $zip -DestinationPath mingit
    Write-Output 'setup: mingit installed'
}

Write-Output 'setup: done'
