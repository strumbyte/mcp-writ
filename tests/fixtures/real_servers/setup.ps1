# Fetch the pinned real MCP servers used by tests/real_servers_e2e.rs.
# No arguments. Idempotent: skips each runtime that is already installed.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Node: package-lock.json is committed; npm ci reproduces it exactly.
# node_modules counts as installed only when the marker written after a
# successful npm ci is present — npm ci clears node_modules itself, so a
# partial tree from an interrupted run is rebuilt, not mistaken for
# installed.
if (Test-Path node\node_modules\.install-complete) {
    Write-Output 'setup: node already installed (node/node_modules present)'
} else {
    Push-Location node
    try {
        npm ci --ignore-scripts
    } finally {
        Pop-Location
    }
    # $ErrorActionPreference does not apply to native exit codes; a failed
    # npm ci must not leave the completion marker behind.
    if ($LASTEXITCODE -ne 0) { throw "setup: npm ci failed ($LASTEXITCODE)" }
    New-Item -ItemType File -Path node\node_modules\.install-complete | Out-Null
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
    # Prefer PATH `python` — actions/setup-python pins that interpreter.
    # `py -3` remains the fallback when no `python` is on PATH.
    if (Get-Command python -ErrorAction SilentlyContinue) {
        python -m venv python\.venv
    } else {
        py -3 -m venv python\.venv
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
# nor covered by package ACEs. Pinned archive, verified by sha256. A
# mingit tree counts as installed only when the marker written after a
# successful extraction is present — a leftover from an interrupted run
# is removed and reinstalled, not mistaken for usable.
$mingitVersion = '2.55.0.4'
$mingitSha256 = '4e03f94c2ffbf70be337e005cee02661c732dbfc81031a078bda9299b9a7d644'
if (Test-Path mingit\.install-complete) {
    Write-Output 'setup: mingit already installed (mingit present)'
} else {
    if (Test-Path mingit) {
        Remove-Item -Recurse -Force mingit
    }
    $zip = Join-Path $env:TEMP "MinGit-$mingitVersion-64-bit.zip"
    Invoke-WebRequest `
        -Uri "https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.4/MinGit-$mingitVersion-64-bit.zip" `
        -OutFile $zip
    $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $mingitSha256) {
        Remove-Item $zip -Force
        throw "setup: mingit sha256 mismatch: expected $mingitSha256, got $actual"
    }
    # Extract to a temp dir beside the destination and move into place
    # only on success — same volume, so the Move-Item is a rename and an
    # interrupted Expand-Archive never leaves a partial mingit tree.
    $extract = Join-Path $PSScriptRoot "MinGit-$mingitVersion-extract"
    if (Test-Path $extract) {
        Remove-Item -Recurse -Force $extract
    }
    Expand-Archive $zip -DestinationPath $extract
    Move-Item -LiteralPath $extract -Destination mingit
    New-Item -ItemType File -Path mingit\.install-complete | Out-Null
    Write-Output 'setup: mingit installed'
}

Write-Output 'setup: done'
