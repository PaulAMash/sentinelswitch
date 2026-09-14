#!/usr/bin/env bash
# Reset the deterministic environment and replay the flagship incident (INC-2026-0042).
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/python -m sentinelswitch demo --reset "$@"
