<#
.SYNOPSIS
    Release unfinished reservations in an abandoned cloud batch.

.DESCRIPTION
    Wrapper around 'python -m app.cloud_batch release <batch-id>'.
    Only releases rules that are still in RESERVED state.
    Rules that were already imported remain intact — their classifications are preserved.
    This script requires an explicit -BatchId and does NOT release automatically.

.EXAMPLE
    .\cloud-release.ps1 -BatchId kaggle-20260904-003
    .\cloud-release.ps1 -BatchId colab-20260904-002
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BatchId
)

$ErrorActionPreference = 'Stop'
$ScriptDir  = $PSScriptRoot
$BackendDir = Join-Path $ScriptDir 'backend'
$Python     = Join-Path $BackendDir '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Write-Host "ERROR: Backend virtual environment not found." -ForegroundColor Red
    Write-Host "  Expected: $Python"
    exit 1
}

# Validate batch ID format (worker-YYYYMMDD-NNN)
if ($BatchId -notmatch '^[a-z][a-z0-9-]{0,31}-\d{8}-\d{3}$') {
    Write-Host "ERROR: Batch ID does not match expected format (e.g. kaggle-20260904-003)." -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '=================================================' -ForegroundColor Yellow
Write-Host "RELEASING BATCH: $BatchId" -ForegroundColor Yellow
Write-Host '=================================================' -ForegroundColor Yellow
Write-Host ''
Write-Host "This will release only UNFINISHED reservations."
Write-Host "Already-imported classifications will be preserved."
Write-Host ''

Push-Location -LiteralPath $BackendDir
try {
    & $Python -m app.cloud_batch release $BatchId
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

Write-Host ''
if ($exitCode -eq 0) {
    Write-Host "Released. Unfinished rules are available again for local or cloud processing." -ForegroundColor Green
} else {
    Write-Host "Release returned exit code $exitCode. Check output above." -ForegroundColor Yellow
}

Write-Host ''
Write-Host '--- Updated Status ---' -ForegroundColor Yellow
Push-Location -LiteralPath $BackendDir
try {
    & $Python -m app.cloud_batch status
} finally {
    Pop-Location
}
Write-Host ''

exit $exitCode
