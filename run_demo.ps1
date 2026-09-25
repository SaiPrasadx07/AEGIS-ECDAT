<#
.SYNOPSIS
    AegisPQC — one-command demo launcher for Windows.

.DESCRIPTION
    Verifies the environment, seeds the fixed demo scenario, and opens the
    dashboard. Run this ten minutes before you present, not thirty seconds
    before.

.PARAMETER WithApi
    Also start the FastAPI service on port 8000 in a separate window, so you can
    show the OpenAPI docs at http://127.0.0.1:8000/docs.

    The dashboard does NOT need this. It calls the backend in-process, so the
    demo works whether or not the API is running.

.EXAMPLE
    .\run_demo.ps1
    .\run_demo.ps1 -WithApi
#>

param(
    [switch]$WithApi
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  AEGIS PQC - DEMO LAUNCHER" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# --- Virtual environment -------------------------------------------------
if (-not (Test-Path ".venv")) {
    Write-Host "[1/4] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
} else {
    Write-Host "[1/4] Virtual environment found." -ForegroundColor Green
}

& ".\.venv\Scripts\Activate.ps1"

# --- Dependencies --------------------------------------------------------
Write-Host "[2/4] Checking dependencies..." -ForegroundColor Yellow
$cryptoOk = $false
try {
    python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey" 2>$null
    if ($LASTEXITCODE -eq 0) { $cryptoOk = $true }
} catch { }

if (-not $cryptoOk) {
    Write-Host "      Installing (this takes about 30 seconds)..." -ForegroundColor Yellow
    python -m pip install --upgrade pip --quiet
    python -m pip install -r requirements.txt --quiet
}

# Prove ML-KEM actually works on this machine before going any further.
$check = python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey as K; k=K.generate(); s,c=k.public_key().encapsulate(); print('OK' if (len(c)==1088 and s==k.decapsulate(c)) else 'FAIL')"
if ($check -ne "OK") {
    Write-Host ""
    Write-Host "  ML-KEM verification FAILED. Do not present until this is fixed." -ForegroundColor Red
    Write-Host "  Try: python -m pip install --upgrade 'cryptography>=49'" -ForegroundColor Red
    exit 1
}
Write-Host "      ML-KEM-768 verified (1088-byte ciphertext, secrets match)." -ForegroundColor Green

# --- Pre-flight ----------------------------------------------------------
# Runs every subsystem check and seeds the full presentation state, including
# the scanner's demo enterprise. Skips the test suite for speed; run
# `.\preflight.ps1` without -Fast at least once on this machine.
Write-Host "[3/4] Running pre-flight checks..." -ForegroundColor Yellow
python -m backend.preflight --fast
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  Pre-flight FAILED. Do not present until this is fixed." -ForegroundColor Red
    exit 1
}

# --- Launch --------------------------------------------------------------
if ($WithApi) {
    Write-Host "[4/4] Starting FastAPI on http://127.0.0.1:8000/docs ..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList @(
        "-NoExit", "-Command",
        "Set-Location '$PSScriptRoot'; .\.venv\Scripts\Activate.ps1; python -m uvicorn backend.main:app --port 8000"
    )
    Start-Sleep -Seconds 3
}

Write-Host "[4/4] Opening the dashboard at http://localhost:8501 ..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Demo order: Vault -> Attacker Hoard -> Q-Day -> Benchmarks" -ForegroundColor Cyan
Write-Host "  Press Ctrl+C in this window to stop." -ForegroundColor DarkGray
Write-Host ""

python -m streamlit run frontend/app.py
