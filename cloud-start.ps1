<#
.SYNOPSIS
    Create Kaggle and/or Colab cloud batch bundles for Qwen V2.2 classification.

.DESCRIPTION
    Wraps 'python -m app.cloud_batch export' for both Kaggle and Colab workers.
    Performs pre-flight checks, detects conflicting active batches, creates portable
    ZIPs, and prints step-by-step next instructions.

    All database writes are performed by the Python backend — this script is a
    user-friendly wrapper only. It never modifies the reservation architecture,
    bypasses ownership logic, or runs inference.

.EXAMPLE
    .\cloud-start.ps1
    .\cloud-start.ps1 -KaggleLimit 2000 -ColabLimit 500
    .\cloud-start.ps1 -KaggleOnly -KaggleLimit 1000
    .\cloud-start.ps1 -ColabOnly
    .\cloud-start.ps1 -StartLocal
    .\cloud-start.ps1 -ForceNew            # create even if active batch exists
    .\cloud-start.ps1 -OpenFolder $false   # don't open Explorer
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 10000)][int]$KaggleLimit = 1000,
    [ValidateRange(1, 10000)][int]$ColabLimit  = 1000,
    [switch]$KaggleOnly,
    [switch]$ColabOnly,
    [switch]$StartLocal,
    [switch]$ForceNew,
    [bool]$OpenFolder = $true
)

$ErrorActionPreference = 'Stop'
$ScriptDir  = $PSScriptRoot
$BackendDir = Join-Path $ScriptDir 'backend'
$Python     = Join-Path $BackendDir '.venv\Scripts\python.exe'
$BatchDir   = Join-Path $ScriptDir 'data\cloud_batches'
$ResultsDir = Join-Path $ScriptDir 'data\cloud_results'

# ──────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ''
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host 'SURICATA CLOUD QWEN — BATCH PREPARATION' -ForegroundColor Cyan
    Write-Host '=================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Invoke-Python {
    param([string[]]$Args)
    Push-Location -LiteralPath $BackendDir
    try {
        & $Python @Args
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

function Get-StatusJson {
    Push-Location -LiteralPath $BackendDir
    try {
        $raw = & $Python -m app.cloud_batch status --json 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        # If --json is not supported, fall back to text parse; return null to skip check
        try { return $raw | ConvertFrom-Json } catch { return $null }
    } finally {
        Pop-Location
    }
}

# ──────────────────────────────────────────────────────────────
# PRE-FLIGHT: virtualenv
# ──────────────────────────────────────────────────────────────
Write-Banner

Write-Section 'Pre-flight checks'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Write-Host "ERROR: Backend virtual environment not found." -ForegroundColor Red
    Write-Host "  Expected: $Python"
    Write-Host "  Run:  cd backend; python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
    exit 1
}
Write-Host "  [OK] Python venv: $Python"

# PRE-FLIGHT: module reachable
Push-Location -LiteralPath $BackendDir
try {
    & $Python -c "import app.cloud_batch" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: app.cloud_batch module is not importable." -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}
Write-Host "  [OK] app.cloud_batch module importable"

# PRE-FLIGHT: DB reachable via status
Write-Section 'Current cloud status'
$statusCode = Invoke-Python @('-m', 'app.cloud_batch', 'status')
if ($statusCode -ne 0) {
    Write-Host "ERROR: Cannot read cloud status. Check database connection." -ForegroundColor Red
    exit 1
}

# PRE-FLIGHT: create output directories
New-Item -ItemType Directory -Force -Path $BatchDir   | Out-Null
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
Write-Host ''
Write-Host "  Results drop folder: $ResultsDir"

# ──────────────────────────────────────────────────────────────
# Conflict detection: look for active batches per worker
# Uses Python to query status and parse active_batches from output
# ──────────────────────────────────────────────────────────────
function Test-ActiveBatch([string]$Worker) {
    Push-Location -LiteralPath $BackendDir
    try {
        # We call status and grep for the worker name with ACTIVE/PREPARING/PARTIALLY_IMPORTED
        $raw = & $Python -m app.cloud_batch status 2>&1
        $pattern = "$Worker-\d{8}-\d{3}\s+\((active|preparing|partially_imported)"
        foreach ($line in $raw) {
            if ($line -match "$Worker-\d{8}-\d{3}") {
                return $line.Trim()
            }
        }
        return $null
    } finally {
        Pop-Location
    }
}

# ──────────────────────────────────────────────────────────────
# Determine which workers to create
# ──────────────────────────────────────────────────────────────
$doKaggle = -not $ColabOnly
$doColab  = -not $KaggleOnly

$kaggleBundlePath = $null
$colabBundlePath  = $null
$kaggleBatchId    = $null
$colabBatchId     = $null

# ──────────────────────────────────────────────────────────────
# KAGGLE EXPORT
# ──────────────────────────────────────────────────────────────
if ($doKaggle) {
    Write-Section "Creating Kaggle batch (limit: $KaggleLimit)"

    $existingKaggle = Test-ActiveBatch 'kaggle'
    if ($existingKaggle -and -not $ForceNew) {
        Write-Host ''
        Write-Host "  WARNING: Existing active Kaggle batch detected:" -ForegroundColor Yellow
        Write-Host "  $existingKaggle" -ForegroundColor Yellow
        Write-Host ''
        Write-Host "  Please complete or release it before creating another:"
        Write-Host "    .\cloud-release.ps1 -BatchId <batch-id>"
        Write-Host ''
        Write-Host "  To override and create anyway: .\cloud-start.ps1 -ForceNew"
        Write-Host ''
        $doKaggle = $false
    } else {
        if ($existingKaggle -and $ForceNew) {
            Write-Host "  [ForceNew] Ignoring existing active Kaggle batch: $existingKaggle" -ForegroundColor Yellow
        }

        Push-Location -LiteralPath $BackendDir
        try {
            $exportOutput = & $Python -m app.cloud_batch export `
                --limit $KaggleLimit `
                --worker kaggle `
                --output-root $BatchDir 2>&1
            $exportExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        foreach ($line in $exportOutput) { Write-Host "  $line" }

        if ($exportExit -ne 0) {
            Write-Host "ERROR: Kaggle batch export failed (exit $exportExit)." -ForegroundColor Red
            exit $exportExit
        }

        # Parse bundle path from output
        foreach ($line in $exportOutput) {
            if ($line -match 'Bundle:\s*(.+\.zip)') {
                $kaggleBundlePath = $Matches[1].Trim()
            }
            if ($line -match 'Cloud batch:\s*(.+)') {
                $kaggleBatchId = $Matches[1].Trim()
            }
        }
    }
}

# ──────────────────────────────────────────────────────────────
# COLAB EXPORT
# ──────────────────────────────────────────────────────────────
if ($doColab) {
    Write-Section "Creating Colab batch (limit: $ColabLimit)"

    $existingColab = Test-ActiveBatch 'colab'
    if ($existingColab -and -not $ForceNew) {
        Write-Host ''
        Write-Host "  WARNING: Existing active Colab batch detected:" -ForegroundColor Yellow
        Write-Host "  $existingColab" -ForegroundColor Yellow
        Write-Host ''
        Write-Host "  Please complete or release it before creating another:"
        Write-Host "    .\cloud-release.ps1 -BatchId <batch-id>"
        Write-Host ''
        Write-Host "  To override: .\cloud-start.ps1 -ForceNew"
        Write-Host ''
        $doColab = $false
    } else {
        if ($existingColab -and $ForceNew) {
            Write-Host "  [ForceNew] Ignoring existing active Colab batch: $existingColab" -ForegroundColor Yellow
        }

        Push-Location -LiteralPath $BackendDir
        try {
            $exportOutput = & $Python -m app.cloud_batch export `
                --limit $ColabLimit `
                --worker colab `
                --output-root $BatchDir 2>&1
            $exportExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }

        foreach ($line in $exportOutput) { Write-Host "  $line" }

        if ($exportExit -ne 0) {
            Write-Host "ERROR: Colab batch export failed (exit $exportExit)." -ForegroundColor Red
            exit $exportExit
        }

        foreach ($line in $exportOutput) {
            if ($line -match 'Bundle:\s*(.+\.zip)') {
                $colabBundlePath = $Matches[1].Trim()
            }
            if ($line -match 'Cloud batch:\s*(.+)') {
                $colabBatchId = $Matches[1].Trim()
            }
        }
    }
}

# ──────────────────────────────────────────────────────────────
# OPTIONAL: start local Qwen
# ──────────────────────────────────────────────────────────────
if ($StartLocal) {
    Write-Section 'Starting local Qwen worker'
    $localScript = Join-Path $ScriptDir 'run-qwen-1000.ps1'
    if (Test-Path -LiteralPath $localScript) {
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$localScript`"" `
            -WindowStyle Normal
        Write-Host "  Local Qwen worker started in a new window."
    } else {
        Write-Host "  WARNING: run-qwen-1000.ps1 not found." -ForegroundColor Yellow
    }
}

# ──────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '=================================================' -ForegroundColor Green
Write-Host 'BUNDLES READY' -ForegroundColor Green
Write-Host '=================================================' -ForegroundColor Green
Write-Host ''

if ($kaggleBundlePath) {
    Write-Host "Kaggle" -ForegroundColor Cyan
    if ($kaggleBatchId) { Write-Host "  Batch: $kaggleBatchId" }
    Write-Host "  Bundle: $kaggleBundlePath" -ForegroundColor White
}

if ($colabBundlePath) {
    Write-Host ''
    Write-Host "Colab" -ForegroundColor Cyan
    if ($colabBatchId) { Write-Host "  Batch: $colabBatchId" }
    Write-Host "  Bundle: $colabBundlePath" -ForegroundColor White
}

Write-Host ''
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host 'NEXT STEPS' -ForegroundColor Cyan
Write-Host '=================================================' -ForegroundColor Cyan
Write-Host ''
$step = 1

if ($kaggleBundlePath) {
    Write-Host "$step. Kaggle:" -ForegroundColor Yellow
    Write-Host "   Upload bundle to Kaggle as a private dataset:"
    Write-Host "   $kaggleBundlePath"
    Write-Host "   Then open qwen_kaggle.ipynb, enable GPU, click Run All."
    Write-Host "   Download the generated *-results.jsonl from the output panel."
    $step++
}

if ($colabBundlePath) {
    Write-Host "$step. Colab:" -ForegroundColor Yellow
    Write-Host "   Open Google Colab, select GPU runtime."
    Write-Host "   Upload bundle to /content:"
    Write-Host "   $colabBundlePath"
    Write-Host "   Open qwen_colab.ipynb and click Run All."
    Write-Host "   Download the generated *-results.jsonl from the Files panel."
    $step++
}

Write-Host "$step. Place downloaded results in:" -ForegroundColor Yellow
Write-Host "   $ResultsDir"
$step++

Write-Host "$step. Import results:" -ForegroundColor Yellow
Write-Host "   .\cloud-import.ps1"
$step++

Write-Host "$step. Check status:" -ForegroundColor Yellow
Write-Host "   .\cloud-status.ps1"
$step++

if (-not $StartLocal) {
    Write-Host ''
    Write-Host "Local Qwen can continue independently:"
    Write-Host "  .\run-qwen-1000.ps1"
    Write-Host "  (or: .\cloud-start.ps1 -StartLocal)"
}

Write-Host ''

# ──────────────────────────────────────────────────────────────
# OPTIONAL: open bundle folder in Explorer
# ──────────────────────────────────────────────────────────────
if ($OpenFolder -and (($kaggleBundlePath -or $colabBundlePath))) {
    if (Test-Path -LiteralPath $BatchDir) {
        Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$BatchDir`""
    }
}
