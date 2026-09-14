#!/usr/bin/env bash
# Rebuild the dashboard, render diagrams, and regenerate every screenshot and media asset.
set -euo pipefail
cd "$(dirname "$0")/.."
( cd frontend && npm run build )
.venv/bin/python scripts/diagrams.py
exec .venv/bin/python scripts/screenshots.py "$@"
