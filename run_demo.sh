#!/usr/bin/env bash
# AegisPQC — one-command demo launcher for macOS and Linux.
#
# Usage:
#   ./run_demo.sh            dashboard only (recommended for the pitch)
#   ./run_demo.sh --with-api also start FastAPI on :8000 for the /docs page
#
# The dashboard does NOT need the API. It calls the backend in-process, so the
# demo works whether or not the API is running.

set -euo pipefail
cd "$(dirname "$0")"

echo ""
echo "=========================================================="
echo "  AEGIS PQC - DEMO LAUNCHER"
echo "=========================================================="
echo ""

if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/4] Virtual environment found."
fi

# shellcheck source=/dev/null
source .venv/bin/activate

echo "[2/4] Checking dependencies..."
if ! python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey" 2>/dev/null; then
    echo "      Installing (this takes about 30 seconds)..."
    python -m pip install --upgrade pip --quiet
    python -m pip install -r requirements.txt --quiet
fi

# Prove ML-KEM actually works here before going any further.
CHECK=$(python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey as K; k=K.generate(); s,c=k.public_key().encapsulate(); print('OK' if (len(c)==1088 and s==k.decapsulate(c)) else 'FAIL')")
if [ "$CHECK" != "OK" ]; then
    echo ""
    echo "  ML-KEM verification FAILED. Do not present until this is fixed."
    echo "  Try: python -m pip install --upgrade 'cryptography>=49'"
    exit 1
fi
echo "      ML-KEM-768 verified (1088-byte ciphertext, secrets match)."

echo "[3/4] Running pre-flight checks..."
if ! python -m backend.preflight --fast; then
    echo ""
    echo "  Pre-flight FAILED. Do not present until this is fixed."
    exit 1
fi

if [ "${1:-}" = "--with-api" ]; then
    echo "[4/4] Starting FastAPI on http://127.0.0.1:8000/docs ..."
    python -m uvicorn backend.main:app --port 8000 &
    sleep 3
fi

echo "[4/4] Opening the dashboard at http://localhost:8501 ..."
echo ""
echo "  Demo order: Vault -> Attacker Hoard -> Q-Day -> Benchmarks"
echo ""
python -m streamlit run frontend/app.py
