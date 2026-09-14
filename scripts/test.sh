#!/usr/bin/env bash
# Backend tests, frontend type-check, and linters.
set -euo pipefail
cd "$(dirname "$0")/.."
.venv/bin/python -m pytest -q
.venv/bin/ruff check backend simulator scripts diagrams/source
( cd frontend && npx tsc -b && npm run lint )
