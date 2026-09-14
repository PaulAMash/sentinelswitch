#!/usr/bin/env bash
# One-shot environment setup: virtualenv, Python deps, Node deps, headless Chromium, dataset, database.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then "$PY" -m venv .venv; fi
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -q -r requirements.txt
.venv/bin/pip install -q -e .
.venv/bin/python -m playwright install chromium
( cd frontend && npm install --no-audit --no-fund )
.venv/bin/python -m sentinelswitch seed --regenerate
echo
echo "SentinelSwitch is ready:"
echo "  make demo               # replay the flagship incident in the terminal"
echo "  make dev                # build the dashboard and serve http://127.0.0.1:8000"
echo "  make validate-security  # run the validation harness"
