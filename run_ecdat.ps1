# Aegis PQC — ECDAT launcher (SIH 2026, PS 26164)
#
# Launches the Enterprise Cryptographic Discovery & Analysis Tool dashboard.
# This is the primary application for SIH 2026.
#
# The Security Lab (the earlier Harvest-Now-Decrypt-Later demonstration) is a
# separate, retained capability launched with run_demo.ps1.

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  AEGIS PQC - ECDAT" -ForegroundColor Cyan
Write-Host "  Enterprise Cryptographic Discovery & Analysis Tool" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path "frontend/ecdat_app.py")) {
    Write-Host "  Run this from the repository root." -ForegroundColor Red
    exit 1
}

python -m streamlit run frontend/ecdat_app.py
