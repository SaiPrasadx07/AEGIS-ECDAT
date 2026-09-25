#!/usr/bin/env bash
# Aegis PQC — ECDAT launcher (SIH 2026, PS 26164)
#
# Launches the Enterprise Cryptographic Discovery & Analysis Tool dashboard.
# This is the primary application for SIH 2026.
#
# The Security Lab (the earlier Harvest-Now-Decrypt-Later demonstration) is a
# separate, retained capability launched with run_demo.sh.
set -euo pipefail

echo ""
echo "  AEGIS PQC - ECDAT"
echo "  Enterprise Cryptographic Discovery & Analysis Tool"
echo ""

if [ ! -f "frontend/ecdat_app.py" ]; then
    echo "  Run this from the repository root." >&2
    exit 1
fi

python -m streamlit run frontend/ecdat_app.py
