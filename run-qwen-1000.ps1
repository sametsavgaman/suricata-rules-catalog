[CmdletBinding()]
param(
    [ValidateRange(1, 1000)][int]$Limit = 1000,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'
$backendPath = Join-Path $PSScriptRoot 'backend'
$pythonPath = Join-Path $backendPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw 'Backend virtual environment missing: backend\.venv\Scripts\python.exe'
}
$ollamaPath = $null
if (-not $Status) {
    # Bound llama-server's host-RAM prompt cache on this 16 GB workstation.
    # A server already running must be restarted to inherit this setting.
    $env:LLAMA_ARG_CACHE_RAM = '512'
    $env:OLLAMA_NUM_PARALLEL = '1'
    $env:OLLAMA_MAX_LOADED_MODELS = '1'
    $ollamaCommand = Get-Command 'ollama.exe' -ErrorAction SilentlyContinue
    if (-not $ollamaCommand) {
        throw 'Ollama executable was not found. Install Ollama before running a local Qwen batch.'
    }
    $ollamaPath = $ollamaCommand.Source
    & $ollamaPath list *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Ollama is not running; starting the local server...'
        $ollamaStdout = Join-Path $backendPath 'ollama-batch.out.log'
        $ollamaStderr = Join-Path $backendPath 'ollama-batch.err.log'
        Start-Process -FilePath $ollamaPath -ArgumentList 'serve' -WindowStyle Hidden `
            -RedirectStandardOutput $ollamaStdout -RedirectStandardError $ollamaStderr
        $ollamaReady = $false
        foreach ($attempt in 1..20) {
            Start-Sleep -Milliseconds 500
            & $ollamaPath list *> $null
            if ($LASTEXITCODE -eq 0) {
                $ollamaReady = $true
                break
            }
        }
        if (-not $ollamaReady) {
            throw 'Ollama could not be started. Inspect backend\ollama-batch.err.log, then retry.'
        }
        Write-Host 'Ollama is ready.'
    }
}
$runnerArgs = @('-u', '-m', 'app.evaluation.run_qwen_catalog_batch', '--limit', "$Limit")
if ($Status) { $runnerArgs += '--status' }
$batchExitCode = 130
Push-Location -LiteralPath $backendPath
try {
    & $pythonPath @runnerArgs
    $batchExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $batchExitCode
