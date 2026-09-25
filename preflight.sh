#!/usr/bin/env bash
# AegisPQC pre-flight validation.
#
#   ./preflight.sh          full check, including the test suite
#   ./preflight.sh --fast   skip the test suite

set -euo pipefail
cd "$(dirname "$0")"

if [ -f ".venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    source .venv/bin/activate
fi

python -m backend.preflight "$@"
