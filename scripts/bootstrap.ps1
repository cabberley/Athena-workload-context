$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPath = Join-Path $repoRoot '.venv'
$python = Join-Path $venvPath 'Scripts\python.exe'

if (-not (Test-Path $python)) {
    python -m venv $venvPath
}

& $python -m pip install --upgrade pip
& $python -m pip install -e "${repoRoot}[dev]"

Write-Host 'Athena development environment is ready.'
