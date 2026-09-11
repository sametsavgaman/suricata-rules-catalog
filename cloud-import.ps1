<#
.SYNOPSIS
    Import downloaded cloud batch results into the local database.

.DESCRIPTION
    Scans data\cloud_results\ (and optionally ~/Downloads) for *-results.jsonl files,
    shows what will be imported, and calls 'python -m app.cloud_batch import' for each.
    All validation and duplicate detection is performed by the Python backend.
    Running this script twice is safe — the backend is idempotent.

.EXAMPLE
    .\cloud-import.ps1
    .\cloud-import.ps1 -ScanDownloads
    .\cloud-import.ps1 -ResultsDir C:\custom\path
#>
[CmdletBinding()]
param(
    [string]$ResultsDir   = '',
    [switch]$ScanDownloads,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$ScriptDir  = $PSScriptRoot
$BackendDir = Join-Path $ScriptDir 'backend'
$Python     = Join-Path $BackendDir '.venv\Scripts\python.exe'

if (-not $ResultsDir) {
    $ResultsDir = Join-Path $ScriptDir 'data\cloud_results'
}

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ''
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host 'SURICATA CLOUD QWEN — IMPORT RESULTS' -ForegroundColor Cyan
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Invoke-PythonImport([string]$FilePath) {
    Push-Location -LiteralPath $BackendDir
    try {
        & $Python -m app.cloud_batch import $FilePath
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

function Get-BatchId([string]$FilePath) {
    try {
        $firstLine = Get-Content -LiteralPath $FilePath -TotalCount 1 -Encoding UTF8
        if (-not $firstLine) { return $null }
        $obj = $firstLine | ConvertFrom-Json -ErrorAction Stop
        return $obj.batch_id
    } catch {
        return $null
    }
}

function Test-ResultFile([string]$FilePath) {
    # Quick sanity: first line must parse as JSON and have format_version field
    try {
        $firstLine = Get-Content -LiteralPath $FilePath -TotalCount 1 -Encoding UTF8
        if (-not $firstLine) { return $false }
        $obj = $firstLine | ConvertFrom-Json -ErrorAction Stop
        return ($null -ne $obj.format_version -and $null -ne $obj.batch_id)
    } catch {
        return $false
    }
}

# ──────────────────────────────────────────────────────────────
# Pre-flight
# ──────────────────────────────────────────────────────────────
Write-Banner

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Write-Host "ERROR: Backend virtual environment not found." -ForegroundColor Red
    Write-Host "  Expected: $Python"
    exit 1
}

New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

# ──────────────────────────────────────────────────────────────
# Collect candidate files
# ──────────────────────────────────────────────────────────────
$candidates = [System.Collections.Generic.List[string]]::new()

# Primary: data\cloud_results\
if (Test-Path -LiteralPath $ResultsDir) {
    Get-ChildItem -LiteralPath $ResultsDir -Filter '*-results.jsonl' -File |
        ForEach-Object { $candidates.Add($_.FullName) }
}

# Secondary: ~/Downloads (opt-in only)
if ($ScanDownloads) {
    $downloadsDir = [System.IO.Path]::Combine($env:USERPROFILE, 'Downloads')
    if (Test-Path -LiteralPath $downloadsDir) {
        Get-ChildItem -LiteralPath $downloadsDir -Filter '*-results.jsonl' -File |
            ForEach-Object {
                if ($candidates -notcontains $_.FullName) {
                    $candidates.Add($_.FullName)
                }
            }
    }
}

if ($candidates.Count -eq 0) {
    Write-Host "No *-results.jsonl files found in:" -ForegroundColor Yellow
    Write-Host "  $ResultsDir"
    if (-not $ScanDownloads) {
        Write-Host ''
        Write-Host "Place downloaded results files there, or use -ScanDownloads to also check ~/Downloads."
        Write-Host "Expected filename pattern:  kaggle-YYYYMMDD-NNN-results.jsonl"
    }
    exit 0
}

# ──────────────────────────────────────────────────────────────
# Show what will be imported
# ──────────────────────────────────────────────────────────────
Write-Host "Found $($candidates.Count) result file(s):" -ForegroundColor Green
Write-Host ''

$validFiles   = [System.Collections.Generic.List[string]]::new()
$invalidFiles = [System.Collections.Generic.List[string]]::new()

foreach ($file in $candidates) {
    $batchId = Get-BatchId $file
    $valid   = Test-ResultFile $file
    $size    = (Get-Item $file).Length
    if ($valid) {
        $validFiles.Add($file)
        Write-Host "  [VALID]  $(Split-Path $file -Leaf)" -ForegroundColor White
        if ($batchId) { Write-Host "           Batch: $batchId" }
        Write-Host "           Size:  $([math]::Round($size/1KB, 1)) KB"
    } else {
        $invalidFiles.Add($file)
        Write-Host "  [SKIP]   $(Split-Path $file -Leaf)  (not a valid cloud result file)" -ForegroundColor DarkGray
    }
    Write-Host ''
}

if ($DryRun) {
    Write-Host "[DryRun] No imports performed." -ForegroundColor Yellow
    exit 0
}

if ($validFiles.Count -eq 0) {
    Write-Host "No valid result files to import." -ForegroundColor Yellow
    exit 0
}

# ──────────────────────────────────────────────────────────────
# Import each valid file
# ──────────────────────────────────────────────────────────────
$totalImported      = 0
$totalAlreadyPresent = 0
$totalRejected      = 0
$fileErrors         = 0

foreach ($file in $validFiles) {
    $name = Split-Path $file -Leaf
    Write-Host '─────────────────────────────────────────────────' -ForegroundColor DarkGray
    Write-Host "Importing: $name" -ForegroundColor Cyan
    Write-Host ''

    Push-Location -LiteralPath $BackendDir
    try {
        $output = & $Python -m app.cloud_batch import $file 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    foreach ($line in $output) {
        Write-Host "  $line"
        if ($line -match 'Imported:\s*(\d+)')        { $totalImported       += [int]$Matches[1] }
        if ($line -match 'Already present:\s*(\d+)') { $totalAlreadyPresent += [int]$Matches[1] }
        if ($line -match 'Rejected:\s*(\d+)')        { $totalRejected       += [int]$Matches[1] }
    }

    if ($exitCode -ne 0) {
        Write-Host "  WARNING: import returned exit code $exitCode for $name" -ForegroundColor Yellow
        $fileErrors++
    }
}

# ──────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '=================================================' -ForegroundColor Green
Write-Host 'IMPORT COMPLETE' -ForegroundColor Green
Write-Host '=================================================' -ForegroundColor Green
Write-Host ''
Write-Host "Files processed:  $($validFiles.Count)"
Write-Host "Imported:         $totalImported"
Write-Host "Already present:  $totalAlreadyPresent"
Write-Host "Rejected:         $totalRejected"
if ($fileErrors -gt 0) {
    Write-Host "File errors:      $fileErrors" -ForegroundColor Yellow
}
Write-Host ''

# ──────────────────────────────────────────────────────────────
# Status summary
# ──────────────────────────────────────────────────────────────
Write-Host '--- Current Status ---' -ForegroundColor Yellow
Push-Location -LiteralPath $BackendDir
try {
    & $Python -m app.cloud_batch status
} finally {
    Pop-Location
}
Write-Host ''
