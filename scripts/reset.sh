#!/usr/bin/env bash
# Restore the baseline state: Gi1/0/23 back in VLAN 20, flagship evidence removed, validation re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/python -m sentinelswitch reset
