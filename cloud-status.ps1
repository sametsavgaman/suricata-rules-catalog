<#
.SYNOPSIS
    Show Qwen V2.2 cloud batch status.

.DESCRIPTION
    Wrapper around 'python -m app.cloud_batch status'.
    Read-only: performs zero inference and no database writes.

.EXAMPLE
    .\cloud-status.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ScriptDir  = $PSScriptRoot
$BackendDir = Join-Path $ScriptDir 'backend'
$Python     = Join-Path $BackendDir '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Write-Host "ERROR: Backend virtual environment not found." -ForegroundColor Red
    Write-Host "  Expected: $Python"
    exit 1
}

Write-Host ''
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host 'QWEN CATALOG STATUS' -ForegroundColor Cyan
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host ''

Push-Location -LiteralPath $BackendDir
try {
    & $Python -m app.cloud_batch status
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host ''
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host ''

exit $exitCode
