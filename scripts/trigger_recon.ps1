# Recon Pipeline V3 - Local Trigger
# Triggers GitHub Actions workflow with config from .env

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [ValidateSet("full", "phase1", "phase1_5", "phase2", "phase3", "phase4", "run_spec")]
    [string]$Phase = "full",

    [string]$RunSpecPath = "",

    [ValidateSet("catpaw", "openai")]
    [string]$LLMBackend = "openai",

    [int]$MaxWorkers = 30,

    [switch]$Wait,

    [switch]$Watch
)

# Read .env for LLM config
$envContent = Get-Content ".env" -Raw -ErrorAction SilentlyContinue
$envConfig = @{}
if ($envContent) {
    foreach ($line in $envContent -split "`n") {
        $line = $line.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line -match '^(.+?)=(.+)$') {
            $envConfig[$matches[1]] = $matches[2].Trim()
        }
    }
}

$llmModel = $envConfig["AIBURP_LLM_MODEL"] ?? "gpt-4o"
$llmBaseUrl = $envConfig["OPENAI_API_BASE"] ?? ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Recon Pipeline V3 - Cloud Trigger" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Target: $Target" -ForegroundColor Yellow
Write-Host "Phase: $Phase" -ForegroundColor Yellow
Write-Host "LLM: $LLMBackend ($llmModel)" -ForegroundColor Yellow
Write-Host "Workers: $MaxWorkers" -ForegroundColor Yellow
Write-Host ""

# Check gh CLI
$ghVersion = gh --version 2>$null
if (-not $ghVersion) {
    Write-Host "Error: GitHub CLI (gh) not found" -ForegroundColor Red
    exit 1
}

$ghAuth = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Not logged in" -ForegroundColor Red
    Write-Host "Run: gh auth login" -ForegroundColor Yellow
    exit 1
}

# Trigger workflow
Write-Host "Triggering workflow..." -ForegroundColor Green

$runSpecB64 = ""
if ($Phase -eq "run_spec") {
    if (-not $RunSpecPath) {
        Write-Host "Error: -RunSpecPath is required when -Phase run_spec" -ForegroundColor Red
        exit 1
    }

    try {
        $resolvedRunSpec = Resolve-Path -LiteralPath $RunSpecPath -ErrorAction Stop
        $runSpecBytes = [System.IO.File]::ReadAllBytes($resolvedRunSpec.Path)
        $runSpecB64 = [Convert]::ToBase64String($runSpecBytes)
        Write-Host "RunSpec: $($resolvedRunSpec.Path)" -ForegroundColor Yellow
    } catch {
        Write-Host "Error: failed to read RunSpec file: $_" -ForegroundColor Red
        exit 1
    }
}

try {
    $workflowArgs = @(
        "workflow", "run", "recon-pipeline-v2.yml",
        "-f", "target=$Target",
        "-f", "phase=$Phase",
        "-f", "llm_backend=$LLMBackend",
        "-f", "openai_model=$llmModel",
        "-f", "max_workers=$MaxWorkers"
    )

    if ($runSpecB64) {
        $workflowArgs += @("-f", "run_spec_b64=$runSpecB64")
    }

    $result = gh @workflowArgs 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Workflow triggered!" -ForegroundColor Green
    } else {
        Write-Host "Trigger failed: $result" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Trigger failed: $_" -ForegroundColor Red
    exit 1
}

# Wait and get run ID
Start-Sleep -Seconds 3

if ($Watch -or $Wait) {
    Write-Host ""
    Write-Host "Getting run status..." -ForegroundColor Yellow

    $runs = gh run list --workflow=recon-pipeline-v2.yml --limit 1 --json databaseId,status,convertedStart 2>$null | ConvertFrom-Json

    if ($runs -and $runs.Count -gt 0) {
        $runId = $runs[0].databaseId
        $status = $runs[0].status

        Write-Host "Run ID: $runId" -ForegroundColor Cyan
        Write-Host "Status: $status" -ForegroundColor Cyan
        Write-Host ""

        if ($Watch) {
            Write-Host "Watching run (Ctrl+C to exit)..." -ForegroundColor Yellow
            gh run watch $runId
        } else {
            Write-Host "Waiting for completion..." -ForegroundColor Yellow
            gh run watch $runId --exit-status
        }

        Write-Host ""
        Write-Host "Downloading results..." -ForegroundColor Green

        $outputDir = "recon/out/$Target"
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

        gh run download $runId --dir $outputDir 2>$null

        if (Test-Path $outputDir) {
            Write-Host "Results saved to: $outputDir" -ForegroundColor Green

            $summaryFile = Get-ChildItem -Path $outputDir -Recurse -Filter "summary.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($summaryFile) {
                Write-Host ""
                Write-Host "===== Summary =====" -ForegroundColor Cyan
                Get-Content $summaryFile.FullName
            }
        }
    }
} else {
    Write-Host ""
    Write-Host "Tips:" -ForegroundColor Gray
    Write-Host "  Use -Watch to monitor in real-time" -ForegroundColor Gray
    Write-Host "  Use -Wait to wait for completion" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Check status: gh run list --workflow=recon-pipeline-v2.yml" -ForegroundColor Gray
}
